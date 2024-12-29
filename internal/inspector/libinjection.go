package inspector

import (
	"fmt"

	"github.com/sitebatch/waffle-go/internal/action"
	"github.com/sitebatch/waffle-go/internal/inspector/libinjection"
)

type LibInjectionSQLIInspector struct{}
type LibInjectionXSSInspector struct{}

type LibInjectionSQLIInspectorArgs struct {
	InspectTargetOptions []InspectTargetOptions
}

type LibInjectionXSSInspectorArgs struct {
	InspectTargetOptions []InspectTargetOptions
}

func (r *LibInjectionSQLIInspectorArgs) IsArgOf() string {
	return string(LibInjectionSQLIInspectorName)
}

func (r *LibInjectionXSSInspectorArgs) IsArgOf() string {
	return string(LibInjectionXSSInspectorName)
}

func NewLibInjectionSQLIInspector() Inspector {
	return &LibInjectionSQLIInspector{}
}

func NewLibInjectionXSSInspector() Inspector {
	return &LibInjectionXSSInspector{}
}

func (r *LibInjectionSQLIInspector) Name() InspectorName {
	return LibInjectionSQLIInspectorName
}

func (r *LibInjectionXSSInspector) Name() InspectorName {
	return LibInjectionXSSInspectorName
}

func (r *LibInjectionSQLIInspector) IsSupportTarget(target InspectTarget) bool {
	return true
}

func (r *LibInjectionXSSInspector) IsSupportTarget(target InspectTarget) bool {
	return true
}

func (r *LibInjectionSQLIInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error {
	args, ok := inspectorArgs.(*LibInjectionSQLIInspectorArgs)
	if !ok {
		return fmt.Errorf("invalid args")
	}

	for _, target := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[InspectTarget(target.Target)]; !ok {
			continue
		}

		values := inspectData.Target[InspectTarget(target.Target)].GetValues(
			WithParamNames(target.Params),
		)

		for _, value := range values {
			err := libinjection.IsSQLiPayload(value)
			if err != nil {
				return &action.DetectionError{Reason: fmt.Sprintf("detected sql injection payload: %s", err)}
			}
		}
	}

	return nil
}

func (r *LibInjectionXSSInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error {
	args, ok := inspectorArgs.(*LibInjectionXSSInspectorArgs)
	if !ok {
		return fmt.Errorf("invalid args")
	}

	for _, target := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[InspectTarget(target.Target)]; !ok {
			continue
		}

		values := inspectData.Target[InspectTarget(target.Target)].GetValues(
			WithParamNames(target.Params),
		)

		for _, value := range values {
			err := libinjection.IsXSSPayload(value)
			if err != nil {
				return &action.DetectionError{Reason: fmt.Sprintf("detected xss payload: %s", err)}
			}
		}
	}

	return nil
}
