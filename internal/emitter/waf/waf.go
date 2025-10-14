package waf

import (
	"maps"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type WAF interface {
	// Inspect inspects the given data and returns detection events and an optional block error.
	Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]DetectionEvent, error)
}

type waf struct {
	rules         *rule.RuleSet
	ruleEvaluator *RuleEvaluator
}

func NewWAF(rules *rule.RuleSet) WAF {
	inspectors := make(map[string]inspector.Inspector)
	maps.Copy(inspectors, inspector.NewInspector())

	return &waf{
		rules:         rules,
		ruleEvaluator: NewRuleEvaluator(inspectors),
	}
}

func (w *waf) Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]DetectionEvent, error) {
	var detectionEvents []DetectionEvent

	for _, rule := range w.rules.Rules {
		results, doBlock := w.ruleEvaluator.Eval(rule, data)

		for _, result := range results {
			event := NewDetectionEvent(
				data.WafOperationContext,
				result.Rule,
				result.InspectBy,
				result.InspectResult.Message,
				result.InspectResult.Payload,
			)
			detectionEvents = append(detectionEvents, event)
		}

		if doBlock {
			return detectionEvents, &action.BlockError{
				RuleID:    rule.ID,
				Inspector: results[0].InspectBy,
			}
		}
	}

	return detectionEvents, nil
}
