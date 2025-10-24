package inspector

import (
	"errors"
	"fmt"

	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	regexp "github.com/wasilibs/go-re2"
)

type MatchListInspector struct{}

type MatchListInspectorArgs struct {
	List                 []string
	InspectTargetOptions []InspectTargetOptions
}

func (m *MatchListInspectorArgs) IsArgOf() string {
	return string(MatchListInspectorName)
}

func NewMatchListInspector() Inspector {
	return &MatchListInspector{}
}

func (m *MatchListInspector) IsSupportTarget(target InspectTarget) bool {
	return true
}

func (m *MatchListInspector) Name() InspectorName {
	return MatchListInspectorName
}

func (m *MatchListInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*InspectResult, error) {
	args, ok := inspectorArgs.(*MatchListInspectorArgs)
	if !ok {
		return nil, errors.New("invalid args, not MatchListInspectorArgs")
	}

	for _, opt := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[opt.Target]; !ok {
			continue
		}

		values := inspectData.Target[opt.Target].GetValues(
			types.WithParamNames(opt.Params),
		)

		for _, value := range values {
			for _, listValue := range args.List {
				re, err := regexp.Compile(listValue)
				if err != nil {
					handler.GetErrorHandler().HandleError(err)
					continue
				}

				if re.MatchString(value) {
					return &InspectResult{
						Target:  opt.Target,
						Payload: value,
						Message: fmt.Sprintf("Suspicious pattern detected: '%s' matches regex '%s'", value, listValue),
					}, nil
				}
			}
		}
	}

	return nil, nil
}
