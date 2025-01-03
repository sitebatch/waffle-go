package inspector

import (
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/log"
)

type RegexInspector struct{}
type RegexInspectorArgs struct {
	Regex                string
	InspectTargetOptions []InspectTargetOptions
}

func (r *RegexInspectorArgs) IsArgOf() string {
	return string(RegexInspectorName)
}

func NewRegexInspector() Inspector {
	return &RegexInspector{}
}

func (r *RegexInspector) Name() InspectorName {
	return RegexInspectorName
}

func (r *RegexInspector) IsSupportTarget(target InspectTarget) bool {
	return true
}

func (r *RegexInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) error {
	args, ok := inspectorArgs.(*RegexInspectorArgs)
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
			matched, err := regexp.MatchString(args.Regex, value)
			if err != nil {
				log.Error("regex compile error, skip inspect: %v", err)
				continue
			}

			if matched {
				return &action.DetectionError{Reason: fmt.Sprintf("detected match %s", args.Regex)}
			}
		}
	}

	return nil
}
