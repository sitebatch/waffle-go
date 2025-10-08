package inspector

import (
	"errors"
	"fmt"

	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"github.com/sitebatch/waffle-go/internal/log"
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

func (m *MatchListInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*SuspiciousResult, error) {
	args, ok := inspectorArgs.(*MatchListInspectorArgs)
	if !ok {
		return nil, errors.New("invalid args, not MatchListInspectorArgs")
	}

	for _, target := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[InspectTarget(target.Target)]; !ok {
			continue
		}

		values := inspectData.Target[InspectTarget(target.Target)].GetValues(
			types.WithParamNames(target.Params),
		)

		for _, value := range values {
			for _, listValue := range args.List {
				re, err := regexp.Compile(listValue)
				if err != nil {
					log.Error("regex compile error, skip inspect: %v", err)
					continue
				}

				if re.MatchString(value) {
					return &SuspiciousResult{
						Payload: value,
						Message: fmt.Sprintf("Suspicious pattern detected: '%s' matches regex '%s'", value, listValue),
					}, nil
				}
			}
		}
	}

	return nil, nil
}
