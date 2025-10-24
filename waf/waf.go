package waf

import (
	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type WAF interface {
	// Inspect inspects the given data and returns detection events and an optional block error.
	Inspect(data inspector.InspectData) ([]DetectionEvent, error)
}

type waf struct {
	rules         *rule.RuleSet
	ruleEvaluator *RuleEvaluator
}

func NewWAF(rules *rule.RuleSet) WAF {
	return &waf{
		rules:         rules,
		ruleEvaluator: NewRuleEvaluator(inspector.NewInspector()),
	}
}

func (w *waf) Inspect(data inspector.InspectData) ([]DetectionEvent, error) {
	var detectionEvents []DetectionEvent

	for _, rule := range w.rules.Rules {
		results, doBlock := w.ruleEvaluator.Eval(rule, data)

		for _, result := range results {
			detectionEvents = append(detectionEvents, NewDetectionEvent(data.WafOperationContext, *result))
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
