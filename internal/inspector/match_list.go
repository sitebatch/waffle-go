package inspector

import (
	"fmt"

	"github.com/sitebatch/waffle-go/internal/action"
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

func (m *MatchListInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error {
	args, ok := inspectorArgs.(*MatchListInspectorArgs)
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
			for _, listValue := range args.List {
				re, err := regexp.Compile(listValue)
				if err != nil {
					log.Error("regex compile error, skip inspect: %v", err)
					continue
				}

				if re.MatchString(value) {
					return &action.DetectionError{Reason: fmt.Sprintf("detected match: %s", listValue)}
				}
			}
		}
	}

	return nil
}
