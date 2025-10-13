package inspector

import (
	"fmt"

	"github.com/sitebatch/waffle-go/internal/inspector/lfi"
)

type LFIInspector struct{}

type LFIInspectorArgs struct{}

func (a *LFIInspectorArgs) IsArgOf() string {
	return string(LFIInspectorName)
}

func NewLFIInspector() Inspector {
	return &LFIInspector{}
}

func (i *LFIInspector) Name() InspectorName {
	return LFIInspectorName
}

func (i *LFIInspector) IsSupportTarget(target InspectTarget) bool {
	return target == InspectTargetOSFileOpen
}

func (i *LFIInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*InspectResult, error) {
	inspectValue := inspectData.Target[InspectTargetOSFileOpen]

	if inspectValue == nil {
		return nil, nil
	}

	filePath := inspectValue.GetValue()

	if lfi.IsAttemptDirectoryTraversal(filePath) {
		return &InspectResult{
			Payload: filePath,
			Message: fmt.Sprintf("detected attempt directory traversal: %s", filePath),
		}, nil
	}

	if lfi.IsSensitiveFilePath(filePath) {
		return &InspectResult{
			Payload: filePath,
			Message: fmt.Sprintf("detected sensitive file path access: %s", filePath),
		}, nil
	}

	return nil, nil
}
