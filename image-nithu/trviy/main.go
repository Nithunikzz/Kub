package artifact

import (
	"context"
	"errors"
	"fmt"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy-db/pkg/db"
	tcache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	local2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/remote"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/policy"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	types "github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
)

// TargetKind represents what kind of artifact Trivy scans
type TargetKind string

const (
	TargetContainerImage TargetKind = "image"
	TargetFilesystem     TargetKind = "fs"
	TargetRootfs         TargetKind = "rootfs"
	TargetRepository     TargetKind = "repo"
	TargetImageArchive   TargetKind = "archive"
	TargetSBOM           TargetKind = "sbom"
	TargetVM             TargetKind = "vm"

	devVersion = "dev"
)

var (
	defaultPolicyNamespaces = []string{
		"appshield",
		"defsec",
		"builtin",
	}
	SkipScan = errors.New("skip subsequent processes")
)

// InitializeScanner defines the initialize function signature of scanner
type InitializeScanner func(context.Context, ScannerConfig) (scanner.Scanner, func(), error)

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

type Runner interface {
	// ScanImage scans an image
	ScanImage(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanFilesystem scans a filesystem
	ScanFilesystem(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanRootfs scans rootfs
	ScanRootfs(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanRepository scans repository
	ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanSBOM scans SBOM
	ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanVM scans VM
	ScanVM(ctx context.Context, opts flag.Options) (types.Report, error)
	// Filter filter a report
	Filter(ctx context.Context, opts flag.Options, report types.Report) (types.Report, error)
	// Report a writes a report
	Report(opts flag.Options, report types.Report) error
	// Close closes runner
	Close(ctx context.Context) error
}

type runner struct {
	cache  cache.Cache
	dbOpen bool

	// WASM modules
	module *module.Manager
}

type runnerOption func(*runner)

// WithCacheClient takes a custom cache implementation
// It is useful when Trivy is imported as a library.
func WithCacheClient(c cache.Cache) runnerOption {
	return func(r *runner) {
		r.cache = c
	}
}

// NewRunner initializes Runner that provides scanning functionalities.
// It is possible to return SkipScan and it must be handled by caller.
func NewRunner(ctx context.Context, cliOptions flag.Options, opts ...runnerOption) (Runner, error) {
	r := &runner{}
	for _, opt := range opts {
		opt(r)
	}

	if err := r.initCache(cliOptions); err != nil {
		return nil, xerrors.Errorf("cache error: %w", err)
	}

	// Update the vulnerability database if needed.
	if err := r.initDB(ctx, cliOptions); err != nil {
		return nil, xerrors.Errorf("DB error: %w", err)
	}

	// Initialize WASM modules
	m, err := module.NewManager(ctx, module.Options{
		Dir:            cliOptions.ModuleDir,
		EnabledModules: cliOptions.EnabledModules,
	})
	if err != nil {
		return nil, xerrors.Errorf("WASM module error: %w", err)
	}
	m.Register()
	r.module = m

	return r, nil
}

// Close closes everything
func (r *runner) Close(ctx context.Context) error {
	var errs error
	if err := r.cache.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}

	if r.dbOpen {
		if err := db.Close(); err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	if err := r.module.Close(ctx); err != nil {
		errs = multierror.Append(errs, err)
	}
	return errs
}

func (r *runner) ScanImage(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanner
	switch {
	case opts.Input != "" && opts.ServerAddr == "":
		// Scan image tarball in standalone mode
		s = archiveStandaloneScanner
	case opts.Input != "" && opts.ServerAddr != "":
		// Scan image tarball in client/server mode
		s = archiveRemoteScanner
	case opts.Input == "" && opts.ServerAddr == "":
		// Scan container image in standalone mode
		s = imageStandaloneScanner
	case opts.Input == "" && opts.ServerAddr != "":
		// Scan container image in client/server mode
		s = imageRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanFilesystem(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable scanning of individual package and SBOM files
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeIndividualPkgs...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	return r.scanFS(ctx, opts)
}

func (r *runner) ScanRootfs(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeLockfiles...)

	return r.scanFS(ctx, opts)
}

func (r *runner) scanFS(ctx context.Context, opts flag.Options) (types.Report, error) {
	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan filesystem in standalone mode
		s = filesystemStandaloneScanner
	} else {
		// Scan filesystem in client/server mode
		s = filesystemRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Do not scan OS packages
	opts.VulnType = []string{types.VulnTypeLibrary}

	// Disable the OS analyzers, individual package analyzers and SBOM analyzer
	opts.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan repository in standalone mode
		s = repositoryStandaloneScanner
	} else {
		// Scan repository in client/server mode
		s = repositoryRemoteScanner
	}
	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error) {
	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan cycloneDX in standalone mode
		s = sbomStandaloneScanner
	} else {
		// Scan cycloneDX in client/server mode
		s = sbomRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanVM(ctx context.Context, opts flag.Options) (types.Report, error) {
	// TODO: Does VM scan disable lock file..?
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan virtual machine in standalone mode
		s = vmStandaloneScanner
	} else {
		// Scan virtual machine in client/server mode
		s = vmRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) scanArtifact(ctx context.Context, opts flag.Options, initializeScanner InitializeScanner) (types.Report, error) {
	report, err := scan(ctx, opts, initializeScanner, r.cache)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	return report, nil
}

func (r *runner) Filter(ctx context.Context, opts flag.Options, report types.Report) (types.Report, error) {
	// Filter results
	err := result.Filter(ctx, report, opts.FilterOpts())
	if err != nil {
		return types.Report{}, xerrors.Errorf("filtering error: %w", err)
	}

	return report, nil
}

func (r *runner) Report(opts flag.Options, report types.Report) error {
	if err := pkgReport.Write(report, opts); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	return nil
}

func (r *runner) initDB(ctx context.Context, opts flag.Options) error {
	if err := r.initJavaDB(opts); err != nil {
		return err
	}

	// When scanning config files or running as client mode, it doesn't need to download the vulnerability database.
	if opts.ServerAddr != "" || !opts.Scanners.Enabled(types.VulnerabilityScanner) {
		return nil
	}

	// download the database file
	noProgress := opts.Quiet || opts.NoProgress
	if err := operation.DownloadDB(ctx, opts.AppVersion, opts.CacheDir, opts.DBRepository, noProgress, opts.SkipDBUpdate, opts.RegistryOpts()); err != nil {
		return err
	}

	if opts.DownloadDBOnly {
		return SkipScan
	}

	if err := db.Init(opts.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	r.dbOpen = true

	return nil
}

func (r *runner) initJavaDB(opts flag.Options) error {
	// When running as server mode, it doesn't need to download the Java database.
	if opts.Listen != "" {
		return nil
	}

	// If vulnerability scanning and SBOM generation are disabled, it doesn't need to download the Java database.
	if !opts.Scanners.Enabled(types.VulnerabilityScanner) &&
		!slices.Contains(ftypes.SupportedSBOMFormats, opts.Format) {
		return nil
	}

	// Update the Java DB
	noProgress := opts.Quiet || opts.NoProgress
	javadb.Init(opts.CacheDir, opts.JavaDBRepository, opts.SkipJavaDBUpdate, noProgress, opts.Insecure)
	if opts.DownloadJavaDBOnly {
		if err := javadb.Update(); err != nil {
			return xerrors.Errorf("Java DB error: %w", err)
		}
		return SkipScan
	}

	return nil
}

func (r *runner) initCache(opts flag.Options) error {
	// Skip initializing cache when custom cache is passed
	if r.cache != nil {
		return nil
	}

	// client/server mode
	if opts.ServerAddr != "" {
		remoteCache := tcache.NewRemoteCache(opts.ServerAddr, opts.CustomHeaders, opts.Insecure)
		r.cache = tcache.NopCache(remoteCache)
		return nil
	}

	// standalone mode
	fsutils.SetCacheDir(opts.CacheDir)
	cacheClient, err := operation.NewCache(opts.CacheOptions)
	if err != nil {
		return xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	log.Logger.Debugf("cache dir:  %s", fsutils.CacheDir())

	if opts.Reset {
		defer cacheClient.Close()
		if err = cacheClient.Reset(); err != nil {
			return xerrors.Errorf("cache reset error: %w", err)
		}
		return SkipScan
	}

	if opts.ResetPolicyBundle {
		c, err := policy.NewClient(fsutils.CacheDir(), true)
		if err != nil {
			return xerrors.Errorf("failed to instantiate policy client: %w", err)
		}
		if err := c.Clear(); err != nil {
			return xerrors.Errorf("failed to remove the cache: %w", err)
		}
		return SkipScan
	}

	if opts.ClearCache {
		defer cacheClient.Close()
		if err = cacheClient.ClearArtifacts(); err != nil {
			return xerrors.Errorf("cache clear error: %w", err)
		}
		return SkipScan
	}

	r.cache = cacheClient
	return nil
}

// Run performs artifact scanning
func Run(ctx context.Context, opts flag.Options, targetKind TargetKind) (err error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	if opts.GenerateDefaultConfig {
		log.Logger.Info("Writing the default config to trivy-default.yaml...")
		return viper.SafeWriteConfigAs("trivy-default.yaml")
	}

	r, err := NewRunner(ctx, opts)
	if err != nil {
		if errors.Is(err, SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	var report types.Report
	switch targetKind {
	case TargetContainerImage, TargetImageArchive:
		if report, err = r.ScanImage(ctx, opts); err != nil {
			return xerrors.Errorf("image scan error: %w", err)
		}
	case TargetFilesystem:
		if report, err = r.ScanFilesystem(ctx, opts); err != nil {
			return xerrors.Errorf("filesystem scan error: %w", err)
		}
	case TargetRootfs:
		if report, err = r.ScanRootfs(ctx, opts); err != nil {
			return xerrors.Errorf("rootfs scan error: %w", err)
		}
	case TargetRepository:
		if report, err = r.ScanRepository(ctx, opts); err != nil {
			return xerrors.Errorf("repository scan error: %w", err)
		}
	case TargetSBOM:
		if report, err = r.ScanSBOM(ctx, opts); err != nil {
			return xerrors.Errorf("sbom scan error: %w", err)
		}
	case TargetVM:
		if report, err = r.ScanVM(ctx, opts); err != nil {
			return xerrors.Errorf("vm scan error: %w", err)
		}
	}

	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = r.Report(opts, report); err != nil {
		return xerrors.Errorf("report error: %w", err)
	}

	operation.ExitOnEOL(opts, report.Metadata)
	operation.Exit(opts, report.Results.Failed())

	return nil
}

func disabledAnalyzers(opts flag.Options) []analyzer.Type {
	// Specified analyzers to be disabled depending on scanning modes
	// e.g. The 'image' subcommand should disable the lock file scanning.
	analyzers := opts.DisabledAnalyzers

	// It doesn't analyze apk commands by default.
	if !opts.ScanRemovedPkgs {
		analyzers = append(analyzers, analyzer.TypeApkCommand)
	}

	// Do not analyze programming language packages when not running in 'library'
	if !slices.Contains(opts.VulnType, types.VulnTypeLibrary) {
		analyzers = append(analyzers, analyzer.TypeLanguages...)
	}

	// Do not perform secret scanning when it is not specified.
	if !opts.Scanners.Enabled(types.SecretScanner) {
		analyzers = append(analyzers, analyzer.TypeSecret)
	}

	// Do not perform misconfiguration scanning when it is not specified.
	if !opts.Scanners.AnyEnabled(types.MisconfigScanner, types.RBACScanner) {
		analyzers = append(analyzers, analyzer.TypeConfigFiles...)
	}

	// Scanning file headers and license files is expensive.
	// It is performed only when '--scanners license' and '--license-full' are specified together.
	if !opts.Scanners.Enabled(types.LicenseScanner) || !opts.LicenseFull {
		analyzers = append(analyzers, analyzer.TypeLicenseFile)
	}

	// Parsing jar files requires Java-db client
	// But we don't create client if vulnerability analysis is disabled and SBOM format is not used
	// We need to disable jar analyzer to avoid errors
	// TODO disable all languages that don't contain license information for this case
	if !opts.Scanners.Enabled(types.VulnerabilityScanner) && !slices.Contains(types.SupportedSBOMFormats, opts.Format) {
		analyzers = append(analyzers, analyzer.TypeJar)
	}

	// Do not perform misconfiguration scanning on container image config
	// when it is not specified.
	if !opts.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		analyzers = append(analyzers, analyzer.TypeHistoryDockerfile)
	}

	if len(opts.SBOMSources) == 0 {
		analyzers = append(analyzers, analyzer.TypeExecutable)
	}

	return analyzers
}

func initScannerConfig(opts flag.Options, cacheClient cache.Cache) (ScannerConfig, types.ScanOptions, error) {
	target := opts.Target
	if opts.Input != "" {
		target = opts.Input
	}

	if opts.Compliance.Spec.ID != "" {
		// set scanners types by spec
		scanners, err := opts.Compliance.Scanners()
		if err != nil {
			return ScannerConfig{}, types.ScanOptions{}, xerrors.Errorf("scanner error: %w", err)
		}

		opts.Scanners = scanners
		opts.ImageConfigScanners = nil
		// TODO: define image-config-scanners in the spec
		if opts.Compliance.Spec.ID == "docker-cis" {
			opts.Scanners = types.Scanners{types.VulnerabilityScanner}
			opts.ImageConfigScanners = types.Scanners{
				types.MisconfigScanner,
				types.SecretScanner,
			}
		}
	}

	scanOptions := types.ScanOptions{
		VulnType:            opts.VulnType,
		Scanners:            opts.Scanners,
		ImageConfigScanners: opts.ImageConfigScanners, // this is valid only for 'image' subcommand
		ScanRemovedPackages: opts.ScanRemovedPkgs,     // this is valid only for 'image' subcommand
		ListAllPackages:     opts.ListAllPkgs,
		LicenseCategories:   opts.LicenseCategories,
		FilePatterns:        opts.FilePatterns,
		IncludeDevDeps:      opts.IncludeDevDeps,
	}

	if len(opts.ImageConfigScanners) != 0 {
		log.Logger.Infof("Container image config scanners: %q", opts.ImageConfigScanners)
	}

	if opts.Scanners.Enabled(types.VulnerabilityScanner) {
		log.Logger.Info("Vulnerability scanning is enabled")
		log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)
	}

	// ScannerOption is filled only when config scanning is enabled.
	var configScannerOptions misconf.ScannerOption
	if opts.Scanners.Enabled(types.MisconfigScanner) || opts.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		log.Logger.Info("Misconfiguration scanning is enabled")

		var downloadedPolicyPaths []string
		var disableEmbedded bool
		downloadedPolicyPaths, err := operation.InitBuiltinPolicies(context.Background(), opts.CacheDir, opts.Quiet, opts.SkipPolicyUpdate)
		if err != nil {
			if !opts.SkipPolicyUpdate {
				log.Logger.Errorf("Falling back to embedded policies: %s", err)
			}
		} else {
			log.Logger.Debug("Policies successfully loaded from disk")
			disableEmbedded = true
		}
		configScannerOptions = misconf.ScannerOption{
			Trace:                   opts.Trace,
			Namespaces:              append(opts.PolicyNamespaces, defaultPolicyNamespaces...),
			PolicyPaths:             append(opts.PolicyPaths, downloadedPolicyPaths...),
			DataPaths:               opts.DataPaths,
			HelmValues:              opts.HelmValues,
			HelmValueFiles:          opts.HelmValueFiles,
			HelmFileValues:          opts.HelmFileValues,
			HelmStringValues:        opts.HelmStringValues,
			TerraformTFVars:         opts.TerraformTFVars,
			K8sVersion:              opts.K8sVersion,
			DisableEmbeddedPolicies: disableEmbedded,
			// DisableEmbeddedLibraries: disableEmbedded,
			// TfExcludeDownloaded:      opts.TfExcludeDownloaded,
		}
	}

	// Do not load config file for secret scanning
	if opts.Scanners.Enabled(types.SecretScanner) {
		ver := canonicalVersion(opts.AppVersion)
		log.Logger.Info("Secret scanning is enabled")
		log.Logger.Info("If your scanning is slow, please try '--scanners vuln' to disable secret scanning")
		log.Logger.Infof("Please see also https://aquasecurity.github.io/trivy/%s/docs/scanner/secret/#recommendation for faster secret detection", ver)
	} else {
		opts.SecretConfigPath = ""
	}

	if opts.Scanners.Enabled(types.LicenseScanner) {
		if opts.LicenseFull {
			log.Logger.Info("Full license scanning is enabled")
		} else {
			log.Logger.Info("License scanning is enabled")
		}
	}

	// SPDX needs to calculate digests for package files
	var fileChecksum bool
	if opts.Format == types.FormatSPDXJSON || opts.Format == types.FormatSPDX {
		fileChecksum = true
	}

	return ScannerConfig{
		Target:             target,
		ArtifactCache:      cacheClient,
		LocalArtifactCache: cacheClient,
		ServerOption: client.ScannerOption{
			RemoteURL:     opts.ServerAddr,
			CustomHeaders: opts.CustomHeaders,
			Insecure:      opts.Insecure,
		},
		ArtifactOption: artifact.Option{
			DisabledAnalyzers: disabledAnalyzers(opts),
			SkipFiles:         opts.SkipFiles,
			SkipDirs:          opts.SkipDirs,
			FilePatterns:      opts.FilePatterns,
			Offline:           opts.OfflineScan,
			NoProgress:        opts.NoProgress || opts.Quiet,
			Insecure:          opts.Insecure,
			RepoBranch:        opts.RepoBranch,
			RepoCommit:        opts.RepoCommit,
			RepoTag:           opts.RepoTag,
			SBOMSources:       opts.SBOMSources,
			RekorURL:          opts.RekorURL,
			//Platform:          opts.Platform,
			Slow:         opts.Slow,
			AWSRegion:    opts.Region,
			FileChecksum: fileChecksum,

			// For image scanning
			ImageOption: ftypes.ImageOptions{
				RegistryOptions: opts.RegistryOpts(),
				DockerOptions: ftypes.DockerOptions{
					Host: opts.DockerHost,
				},
				ImageSources: opts.ImageSources,
			},

			// For misconfiguration scanning
			MisconfScannerOption: configScannerOptions,

			// For secret scanning
			SecretScannerOption: analyzer.SecretScannerOption{
				ConfigPath: opts.SecretConfigPath,
			},

			// For license scanning
			LicenseScannerOption: analyzer.LicenseScannerOption{
				Full:                      opts.LicenseFull,
				ClassifierConfidenceLevel: opts.LicenseConfidenceLevel,
			},
		},
	}, scanOptions, nil
}

func scan(ctx context.Context, opts flag.Options, initializeScanner InitializeScanner, cacheClient cache.Cache) (
	types.Report, error) {
	scannerConfig, scanOptions, err := initScannerConfig(opts, cacheClient)
	if err != nil {
		return types.Report{}, err
	}
	s, cleanup, err := initializeScanner(ctx, scannerConfig)
	if err != nil {
		return types.Report{}, xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan failed: %w", err)
	}
	return report, nil
}

func canonicalVersion(ver string) string {
	if ver == devVersion {
		return ver
	}
	v, err := semver.Parse(ver)
	if err != nil {
		return devVersion
	}
	// Replace pre-release with "dev"
	// e.g. v0.34.0-beta1+snapshot-1
	if v.IsPreRelease() || v.Metadata() != "" {
		return devVersion
	}
	// Add "v" prefix and cut a patch number, "0.34.0" => "v0.34" for the url
	return fmt.Sprintf("v%d.%d", v.Major(), v.Minor())
}

// imageStandaloneScanner initializes a container image scanner in standalone mode
// $ trivy image alpine:3.15
func imageStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeDockerScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache,
		conf.ArtifactOption.ImageOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// archiveStandaloneScanner initializes an image archive scanner in standalone mode
// $ trivy image --input alpine.tar
func archiveStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, err := initializeArchiveScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

// imageRemoteScanner initializes a container image scanner in client/server mode
// $ trivy image --server localhost:4954 alpine:3.15
func imageRemoteScanner(ctx context.Context, conf ScannerConfig) (
	scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteDockerScanner(ctx, conf.Target, conf.ArtifactCache, conf.ServerOption,
		conf.ArtifactOption.ImageOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the remote docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// archiveRemoteScanner initializes an image archive scanner in client/server mode
// $ trivy image --server localhost:4954 --input alpine.tar
func archiveRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	// Scan tar file
	s, err := initializeRemoteArchiveScanner(ctx, conf.Target, conf.ArtifactCache, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the remote archive scanner: %w", err)
	}
	return s, func() {}, nil
}

// filesystemStandaloneScanner initializes a filesystem scanner in standalone mode
func filesystemStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeFilesystemScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// filesystemRemoteScanner initializes a filesystem scanner in client/server mode
func filesystemRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteFilesystemScanner(ctx, conf.Target, conf.ArtifactCache, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a remote filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// repositoryStandaloneScanner initializes a repository scanner in standalone mode
func repositoryStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRepositoryScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a repository scanner: %w", err)
	}
	return s, cleanup, nil
}

// repositoryRemoteScanner initializes a repository scanner in client/server mode
func repositoryRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteRepositoryScanner(ctx, conf.Target, conf.ArtifactCache, conf.ServerOption,
		conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a remote repository scanner: %w", err)
	}
	return s, cleanup, nil
}

// sbomStandaloneScanner initializes a SBOM scanner in standalone mode
func sbomStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeSBOMScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a cycloneDX scanner: %w", err)
	}
	return s, cleanup, nil
}

// sbomRemoteScanner initializes a SBOM scanner in client/server mode
func sbomRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteSBOMScanner(ctx, conf.Target, conf.ArtifactCache, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a remote cycloneDX scanner: %w", err)
	}
	return s, cleanup, nil
}

// vmStandaloneScanner initializes a VM scanner in standalone mode
func vmStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeVMScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache,
		conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a vm scanner: %w", err)
	}
	return s, cleanup, nil
}

// vmRemoteScanner initializes a VM scanner in client/server mode
func vmRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteVMScanner(ctx, conf.Target, conf.ArtifactCache, conf.ServerOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a remote vm scanner: %w", err)
	}
	return s, cleanup, nil
}
func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, imageOpt types.ImageOptions, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
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

// initializeArchiveScanner is for container image archive scanning in standalone mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)
	typesImage, err := image.NewArchiveImage(filePath)
	if err != nil {
		return scanner.Scanner{}, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, nil
}

// initializeFilesystemScanner is for filesystem scanning in standalone mode
func initializeFilesystemScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)
	artifactArtifact, err := local2.NewArtifact(path, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}

func initializeRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)
	artifactArtifact, cleanup, err := remote.NewArtifact(url, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}

func initializeSBOMScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)
	artifactArtifact, err := sbom.NewArtifact(filePath, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}

func initializeVMScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)
	artifactArtifact, err := vm.NewArtifact(filePath, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}

// initializeRemoteDockerScanner is for container image scanning in client/server mode
// e.g. dockerd, container registry, podman, etc.
func initializeRemoteDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, remoteScanOptions client.ScannerOption, imageOpt types.ImageOptions, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	v := _wireValue
	clientScanner := client.NewScanner(remoteScanOptions, v...)
	typesImage, cleanup, err := image.NewContainerImage(ctx, imageName, imageOpt)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption)
	if err != nil {
		cleanup()
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}

var (
	_wireValue = []client.Option(nil)
)

// initializeRemoteArchiveScanner is for container image archive scanning in client/server mode
// e.g. docker save -o alpine.tar alpine:3.15
func initializeRemoteArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache, remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, error) {
	v := _wireValue
	clientScanner := client.NewScanner(remoteScanOptions, v...)
	typesImage, err := image.NewArchiveImage(filePath)
	if err != nil {
		return scanner.Scanner{}, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, err
	}
	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	return scannerScanner, nil
}

// initializeRemoteFilesystemScanner is for filesystem scanning in client/server mode
func initializeRemoteFilesystemScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache, remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	v := _wireValue
	clientScanner := client.NewScanner(remoteScanOptions, v...)
	artifactArtifact, err := local2.NewArtifact(path, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}

// initializeRemoteRepositoryScanner is for repository scanning in client/server mode
func initializeRemoteRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache, remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	v := _wireValue
	clientScanner := client.NewScanner(remoteScanOptions, v...)
	artifactArtifact, cleanup, err := remote.NewArtifact(url, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}

// initializeRemoteSBOMScanner is for sbom scanning in client/server mode
func initializeRemoteSBOMScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache, remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	v := _wireValue
	clientScanner := client.NewScanner(remoteScanOptions, v...)
	artifactArtifact, err := sbom.NewArtifact(path, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}

// initializeRemoteVMScanner is for vm scanning in client/server mode
func initializeRemoteVMScanner(ctx context.Context, path string, artifactCache cache.ArtifactCache, remoteScanOptions client.ScannerOption, artifactOption artifact.Option) (scanner.Scanner, func(), error) {
	v := _wireValue
	clientScanner := client.NewScanner(remoteScanOptions, v...)
	artifactArtifact, err := vm.NewArtifact(path, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}