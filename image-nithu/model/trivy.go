package model

type RunningImages struct {
	Namespace     string
	Pod           string
	InitContainer *string
	Container     *string
	Image         string
	PullableImage string
}
type results []string
