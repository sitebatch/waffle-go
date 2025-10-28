package inspector

import (
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
)

type RegexInspector struct{}
type RegexInspectorArgs struct {
	Regex string
}

func NewRegexInspector() Inspector {
	return &RegexInspector{}
}

func (r *RegexInspector) IsSupportTarget(target InspectTarget) bool {
	return true
}

func (r *RegexInspector) Inspect(inspectData InspectData, args InspectorArgs) (*InspectResult, error) {
	for _, opt := range args.TargetOptions {
		if _, ok := inspectData.Target[opt.Target]; !ok {
			continue
		}

		values := inspectData.Target[opt.Target].GetValues(
			types.WithParamNames(opt.Params),
		)

		for _, value := range values {
			matched, err := regexp.MatchString(args.RegexInspectorArgs.Regex, value)
			if err != nil {
				handler.GetErrorHandler().HandleError(err)
				continue
			}

			if matched {
				return &InspectResult{
					Target:  opt.Target,
					Payload: value,
					Message: fmt.Sprintf("Suspicious pattern detected: '%s' matches regex '%s'", value, args.RegexInspectorArgs.Regex),
				}, nil
			}
		}
	}

	return nil, nil
}
