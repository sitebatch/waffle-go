package inspector

import (
	"errors"
	"fmt"

	"github.com/sitebatch/waffle-go/internal/inspector/libinjection"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
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

func (r *LibInjectionSQLIInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*InspectResult, error) {
	args, ok := inspectorArgs.(*LibInjectionSQLIInspectorArgs)
	if !ok {
		return nil, errors.New("invalid args, not LibInjectionSQLIInspectorArgs")
	}

	for _, opt := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[opt.Target]; !ok {
			continue
		}

		values := inspectData.Target[opt.Target].GetValues(
			types.WithParamNames(opt.Params),
		)

		for _, value := range values {
			err := libinjection.IsSQLiPayload(value)
			if err != nil {
				return &InspectResult{
					Target:  opt.Target,
					Payload: value,
					Message: fmt.Sprintf("detected sqli payload: %s", err),
				}, nil
			}
		}
	}

	return nil, nil
}

func (r *LibInjectionXSSInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*InspectResult, error) {
	args, ok := inspectorArgs.(*LibInjectionXSSInspectorArgs)
	if !ok {
		return nil, errors.New("invalid args, not LibInjectionXSSInspectorArgs")
	}

	for _, opt := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[opt.Target]; !ok {
			continue
		}

		values := inspectData.Target[opt.Target].GetValues(
			types.WithParamNames(opt.Params),
		)

		for _, value := range values {
			err := libinjection.IsXSSPayload(value)
			if err != nil {
				return &InspectResult{
					Target:  opt.Target,
					Payload: value,
					Message: fmt.Sprintf("detected xss payload: %s", err),
				}, nil
			}
		}
	}

	return nil, nil
}
