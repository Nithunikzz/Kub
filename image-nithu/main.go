package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	fanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/intelops/image-nithu/model"
)

const (
	ImageSourceDocker = "docker"
	ImageSourcePodman = "podman"
	// Add other image sources if needed...
)

var (
	defaultPolicyNamespaces = []string{
		"appshield",
		"defsec",
		"builtin",
	}
	SkipScan = errors.New("skip subsequent processes")
)

type ScannerConfig struct {
	// e.g. image name and file path
	Target string

	// Cache
	ArtifactCache      cache.ArtifactCache
	LocalArtifactCache cache.LocalArtifactCache

	// Client/Server options
	ServerOption client.ScannerOption

	// Artifact options
	ArtifactOption artifact.Option
}

const (
	eventSubject_trivy_images = "METRICS.trivy"
)

type Config struct {
	ImageName    string                   `envconfig:"IMAGE_NAME" default:"alpine:3.10"`
	RemoteURL    string                   `envconfig:"REMOTE_URL" default:"http://localhost:4954"`
	OutputType   string                   `envconfig:"OUTPUT_TYPE" default:"table"`
	ImageSources []fanaltypes.ImageSource // Add the image sources field here
}

func ListImages(kubeconfig *string) ([]model.RunningImages, error) {
	var config *rest.Config
	var err error
	if kubeconfig != nil {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read kubeconfig")
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.Wrap(err, "failed to read kubeconfig")
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create clientset")
	}
	ctx := context.Background()
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list namespaces")
	}

	runningImages := []model.RunningImages{}
	for _, namespace := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(namespace.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list pods")
		}

		for _, pod := range pods.Items {
			for _, initContainerStatus := range pod.Status.InitContainerStatuses {
				pullable := initContainerStatus.ImageID
				if strings.HasPrefix(pullable, "docker-pullable://") {
					pullable = strings.TrimPrefix(pullable, "docker-pullable://")
				}
				runningImage := model.RunningImages{
					Pod:           pod.Name,
					Namespace:     pod.Namespace,
					InitContainer: &initContainerStatus.Name,
					Image:         initContainerStatus.Image,
					PullableImage: pullable,
				}
				runningImages = append(runningImages, runningImage)
			}

			for _, containerStatus := range pod.Status.ContainerStatuses {
				pullable := containerStatus.ImageID
				if strings.HasPrefix(pullable, "docker-pullable://") {
					pullable = strings.TrimPrefix(pullable, "docker-pullable://")
				}
				runningImage := model.RunningImages{
					Pod:           pod.Name,
					Namespace:     pod.Namespace,
					Container:     &containerStatus.Name,
					Image:         containerStatus.Image,
					PullableImage: pullable,
				}
				runningImages = append(runningImages, runningImage)
			}
		}
	}

	// Remove exact duplicates
	cleanedImages := []model.RunningImages{}
	seenImages := make(map[string]bool)
	for _, runningImage := range runningImages {
		if !seenImages[runningImage.PullableImage] {
			cleanedImages = append(cleanedImages, runningImage)
			seenImages[runningImage.PullableImage] = true
		}
	}

	return cleanedImages, nil
}

var conf ScannerConfig

func getConfigurations(kubeconfig string) (Config, error) {
	var config Config
	if err := envconfig.Process("", &config); err != nil {
		return Config{}, errors.Wrap(err, "failed to process environment variables")
	}

	// Set the path to your kubeconfig file

	// Build Kubernetes client configuration from the kubeconfig file
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return Config{}, errors.Wrap(err, "failed to build kubeconfig")
	}

	// Use the cluster server URL from the kubeconfig
	//config.RemoteURL = kubeConfig.Host
	config.ImageSources = []fanaltypes.ImageSource{fanaltypes.DockerImageSource, fanaltypes.RemoteImageSource}
	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return Config{}, errors.Wrap(err, "failed to create Kubernetes client")
	}

	// Retrieve all available resource types
	_, err = client.Discovery().ServerPreferredResources()
	if err != nil {
		return Config{}, errors.Wrap(err, "failed to create Kubernetes client")
	}
	//config.ImageSource = imageSource
	return config, nil
}

func main() {
	kubeconfig := "/home/nithu/JAD/config" // Set the path to your kubeconfig file
	config, err := getConfigurations(kubeconfig)

	if err != nil {
		fmt.Printf("failed to get configurations: %v", err)
	}

	if err := log.InitLogger(true, false); err != nil {
		log.Logger.Fatalf("error happened: %v", xerrors.Errorf("failed to initialize a logger: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	defer cancel()
	// artifactCache, err := cache.NewFSCache(os.Getenv("HOME") + "/var/cache/trivy")
	// fmt.Println(artifactCache)
	// if err != nil {
	// 	log.Logger.Fatalf("could not initialize local cache: %v", err)
	// }
	// localCache, err := cache.NewFSCache(os.Getenv("HOME") + "/Library/Caches/trivy")
	// fmt.Println(localCache)
	// if err != nil {
	// 	log.Logger.Fatalf("could not initialize local cache: %v", err)
	// }
	// sc, cleanUp, err := initializeDockerScanner(ctx, config.ImageName, localCache, localCache, fanaltypes.ImageOptions{ImageSources: config.ImageSources}, conf.ArtifactOption)
	// if err != nil {
	// 	log.Logger.Fatalf("could not initialize scan: %v", err)
	// }
	// defer cleanUp()
	//var allVulnerabilities []types.DetectedVulnerability
	//var scanReports []types.Report
	runningImages, err := ListImages(&kubeconfig) // Pass your kubeconfig file path if required
	if err != nil {
		log.Logger.Fatalf("could not list images from the cluster: %v", err)
	}
	for _, runningImage := range runningImages {
		fmt.Printf("Scanning image: %s\n", runningImage.PullableImage)

		// Perform vulnerability scan for the current image
		scanImage(ctx, runningImage.PullableImage, config.ImageSources)
	}
	// for _, runningImage := range runningImages {
	// 	results, err := sc.ScanArtifact(ctx, types.ScanOptions{
	// 		VulnType:            []string{"os", "library"},
	// 		ScanRemovedPackages: true,
	// 		ListAllPackages:     true,
	// 	})
	// 	if err != nil {
	// 		log.Logger.Errorf("could not scan image %s: %v", runningImage.PullableImage, err)
	// 		continue
	// 	}
	// 	scanReports = append(scanReports, results)

	// 	if len(scanReports) > 0 {
	// 		//log.Logger.Infof("Vulnerabilities found in image %s:", allVulnerabilities)
	// 		//log.Logger.Infof("Vulnerabilities found in image %s:", results[0].Vulnerabilities)
	// 		log.Logger.Infof("Vulnerabilities found in image %s:", scanReports)
	// 		if err = report.Write(results, report.Option{
	// 			Output:             os.Stdout,
	// 			Severities:         []dbTypes.Severity{dbTypes.SeverityUnknown},
	// 			Format:             "table",
	// 			OutputTemplate:     "table",
	// 			IncludeNonFailures: false,
	// 		}); err != nil {
	// 			log.Logger.Fatalf("could not write results: %v", xerrors.Errorf("unable to write results: %w", err))
	// 		}
	// 	} else {
	// 		log.Logger.Infof("No vulnerabilities found in image %s", runningImage.PullableImage)
	// 	}
	// }

}

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, imageOpt fanaltypes.ImageOptions, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)
	typesImage, cleanup, err := image.NewContainerImage(ctx, imageName, imageOpt)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption)
	if err != nil {
		cleanup()
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}
func scanImage(ctx context.Context, imageName string, imageSources []fanaltypes.ImageSource) {
	artifactCache, err := cache.NewFSCache(os.Getenv("HOME") + "/var/cache/trivy")
	if err != nil {
		log.Logger.Fatalf("could not initialize local cache: %v", err)
		return
	}

	localCache, err := cache.NewFSCache(os.Getenv("HOME") + "/Library/Caches/trivy")
	if err != nil {
		log.Logger.Fatalf("could not initialize local cache: %v", err)
		return
	}

	sc, cleanUp, err := initializeDockerScanner(ctx, imageName, artifactCache, localCache, fanaltypes.ImageOptions{ImageSources: imageSources}, conf.ArtifactOption)
	if err != nil {
		log.Logger.Fatalf("could not initialize scan: %v", err)
		return
	}
	defer cleanUp()

	results, err := sc.ScanArtifact(ctx, types.ScanOptions{
		VulnType:            []string{"os", "library"},
		ScanRemovedPackages: true,
		ListAllPackages:     true,
	})

	if err != nil {
		log.Logger.Errorf("could not scan image %s: %v", imageName, err)
		return
	}

	if len(results.Results) > 0 {
		log.Logger.Infof("Vulnerabilities found in image %s:", imageName)
		for _, result := range results.Results {
			for _, vuln := range result.Vulnerabilities {
				fmt.Printf("Package: %s\n", vuln.PkgName)
				fmt.Printf("Installed Version: %s\n", vuln.InstalledVersion)
				fmt.Printf("Fixed Version: %s\n", vuln.FixedVersion)
				fmt.Printf("Severity: %s\n", vuln.Severity)
				fmt.Printf("Title: %s\n", vuln.Title)
				fmt.Println("--------------")
			}
		}
	} else {
		log.Logger.Infof("No vulnerabilities found in image %s", imageName)
	}
}

// By making these changes, the vulnerabilities will be printed line by line with each vulnerability's details displayed separately. The loop will go through each vulnerability detected and print its package name, installed version, fixed version, severity, and title. After printing the details for one vulnerability, it will add a line of dashes to separate the information from the next vulnerability.

// This will make the output more human-readable and allow you to see each vulnerability's details individually.
