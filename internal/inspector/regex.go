package inspector

import (
	"errors"
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/sitebatch/waffle-go/internal/inspector/types"
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

func (r *RegexInspector) Inspect(inspectData InspectData, inspectorArgs InspectorArgs) (*SuspiciousResult, error) {
	args, ok := inspectorArgs.(*RegexInspectorArgs)
	if !ok {
		return nil, errors.New("invalid args, not RegexInspectorArgs")
	}

	for _, target := range args.InspectTargetOptions {
		if _, ok := inspectData.Target[InspectTarget(target.Target)]; !ok {
			continue
		}

		values := inspectData.Target[InspectTarget(target.Target)].GetValues(
			types.WithParamNames(target.Params),
		)

		for _, value := range values {
			matched, err := regexp.MatchString(args.Regex, value)
			if err != nil {
				log.Error("regex compile error, skip inspect: %v", err)
				continue
			}

			if matched {
				return &SuspiciousResult{
					Payload: value,
					Message: fmt.Sprintf("Suspicious pattern detected: '%s' matches regex '%s'", value, args.Regex),
				}, nil
			}
		}
	}

	return nil, nil
}
