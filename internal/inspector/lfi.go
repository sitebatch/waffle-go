package inspector

import (
	"github.com/sitebatch/waffle-go/action"
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

func (i *LFIInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error {
	inspectValue := inspectData.Target[InspectTargetOSFileOpen]

	if inspectValue == nil {
		return nil
	}

	filePath := inspectValue.GetValue()

	if lfi.IsAttemptDirectoryTraversal(filePath) {
		return &action.DetectionError{Reason: "detected directory traversal"}
	}

	if lfi.IsSensitiveFilePath(filePath) {
		return &action.DetectionError{Reason: "detected suspicious file path"}
	}

	return nil
}
