package waf

import (
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/rule"
	"golang.org/x/time/rate"
)

func ToInspectTargetOptions(inspectTargets []rule.InspectTarget) []inspector.InspectTargetOptions {
	inspectTargetOptions := make([]inspector.InspectTargetOptions, len(inspectTargets))

	for _, inspectTarget := range inspectTargets {
		inspectTargetOptions = append(inspectTargetOptions, inspector.InspectTargetOptions{
			Target: inspectTarget.Target,
			Params: inspectTarget.Keys,
		})
	}

	return inspectTargetOptions
}

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

func (e *RuleEvaluator) Eval(wafOpCtx *wafcontext.WafOperationContext, r rule.Rule, data inspector.InspectData) ([]*EvalResult, bool) {
	conditionResults := make([]bool, len(r.Conditions))
	results := make([]*EvalResult, 0)

	for i, condition := range r.Conditions {
		conditionResult := false

		for _, target := range condition.InspectTarget {
			if !data.HasTarget(inspector.InspectTarget(target.Target)) {
				continue
			}

			result, err := e.runInspector(condition, data)
			if err != nil {
				log.Error("Error running inspector", "inspector", condition.Inspector, "error", err)
				continue
			}

			if result != nil {
				conditionResult = true

				evalResult := &EvalResult{
					Rule:          r,
					InspectBy:     condition.Inspector,
					InspectResult: result,
				}
				results = append(results, evalResult)

				if r.IsBlockAction() {
					return results, true
				}
			}
		}

		conditionResults[i] = conditionResult
	}

	for _, res := range conditionResults {
		if !res {
			return results, false
		}
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
		return nil, nil
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
		log.Warn("Unknown inspector", "name", i.Name())
		return i.Inspect(data, nil)
	}
}
