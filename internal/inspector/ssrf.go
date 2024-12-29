package inspector

import (
	"github.com/sitebatch/waffle-go/internal/action"
	"github.com/sitebatch/waffle-go/internal/inspector/ssrf"
)

type SSRFInspector struct{}
type SSRFInspectorArgs struct{}

func (a *SSRFInspectorArgs) IsArgOf() string {
	return string(SSRFInspectorName)
}

func NewSSRFInspector() Inspector {
	return &SSRFInspector{}
}

func (i *SSRFInspector) Name() InspectorName {
	return SSRFInspectorName
}

func (i *SSRFInspector) IsSupportTarget(target InspectTarget) bool {
	return target == InspectTargetHttpClientRequestURL
}

func (i *SSRFInspector) Inspect(inspectData InspectData, args InspectorArgs) error {
	inspectValue := inspectData.Target[InspectTargetHttpClientRequestURL]
	if inspectValue == nil {
		return nil
	}

	url := inspectValue.GetValue()

	if err := ssrf.IsCloudMetadataServiceURL(url); err != nil {
		return &action.DetectionError{Reason: err.Error()}
	}

	return nil
}
