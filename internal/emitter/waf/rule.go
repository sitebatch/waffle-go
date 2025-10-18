package waf

import (
	"errors"

	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
	"golang.org/x/time/rate"
)

type RuleEvaluator struct {
	inspectors map[string]inspector.Inspector
}

type EvalResult struct {
	Rule          rule.Rule
	InspectBy     string
	InspectResult *inspector.InspectResult
}

func NewRuleEvaluator(inspectors map[string]inspector.Inspector) *RuleEvaluator {
	return &RuleEvaluator{
		inspectors: inspectors,
	}
}

// Eval evaluates the rule against the given inspect data.
// It returns the evaluation results and whether the rule matched and should block the request.
func (e *RuleEvaluator) Eval(r rule.Rule, data inspector.InspectData) ([]*EvalResult, bool) {
	var results []*EvalResult

	for _, condition := range r.Conditions {
		result, err := e.runInspector(condition, data)
		if err != nil {
			handler.GetErrorHandler().HandleError(err)
			continue
		}

		if result != nil {
			evalResult := &EvalResult{
				Rule:          r,
				InspectBy:     condition.Inspector,
				InspectResult: result,
			}
			results = append(results, evalResult)
		}
	}

	// If any condition is not met, the rule is not matched.
	if len(results) != len(r.Conditions) {
		return nil, false
	}

	for _, res := range results {
		if res.Rule.IsBlockAction() {
			return results, true
		}
	}

	return results, false
}

func (e *RuleEvaluator) runInspector(condition rule.Condition, data inspector.InspectData) (*inspector.InspectResult, error) {
	i, exists := e.inspectors[condition.Inspector]
	if !exists {
		return nil, errors.New("inspector not found: " + condition.Inspector)
	}

	switch i.Name() {
	case inspector.RegexInspectorName:
		return i.Inspect(data, &inspector.RegexInspectorArgs{
			Regex:                condition.Regex,
			InspectTargetOptions: ToInspectTargetOptions(condition.InspectTarget),
		})

	case inspector.MatchListInspectorName:
		return i.Inspect(data, &inspector.MatchListInspectorArgs{
			List:                 condition.MatchList,
			InspectTargetOptions: ToInspectTargetOptions(condition.InspectTarget),
		})

	case inspector.LibInjectionSQLIInspectorName:
		return i.Inspect(data, &inspector.LibInjectionSQLIInspectorArgs{
			InspectTargetOptions: ToInspectTargetOptions(condition.InspectTarget),
		})

	case inspector.LibInjectionXSSInspectorName:
		return i.Inspect(data, &inspector.LibInjectionXSSInspectorArgs{
			InspectTargetOptions: ToInspectTargetOptions(condition.InspectTarget),
		})

	case inspector.SQLiInspectorName:
		return i.Inspect(data, &inspector.SQLiInspectorArgs{})

	case inspector.LFIInspectorName:
		return i.Inspect(data, &inspector.LFIInspectorArgs{})

	case inspector.SSRFInspectorName:
		return i.Inspect(data, &inspector.SSRFInspectorArgs{})

	case inspector.AccountTakeoverInspectorName:
		return i.Inspect(data, &inspector.AccountTakeoverInspectorArgs{
			LoginRateLimitPerSecond: rate.Limit(condition.Threshold),
		})

	default:
		return nil, errors.New("unknown inspector: " + condition.Inspector)
	}
}

func ToInspectTargetOptions(inspectTargets []rule.InspectTarget) []inspector.InspectTargetOptions {
	var inspectTargetOptions []inspector.InspectTargetOptions

	for _, inspectTarget := range inspectTargets {
		inspectTargetOptions = append(inspectTargetOptions, inspector.InspectTargetOptions{
			Target: inspector.InspectTarget(inspectTarget.Target),
			Params: inspectTarget.Keys,
		})
	}

	return inspectTargetOptions
}
