package waf

import (
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type WAF interface {
	// Inspect inspects the given data and returns detection events and an optional block error.
	Inspect(data inspector.InspectData) ([]DetectionEvent, error)
}

type waf struct {
	ruleSet       *rule.RuleSet
	ruleEvaluator *RuleEvaluator
}

func NewWAF(ruleSet *rule.RuleSet) WAF {
	return &waf{
		ruleSet:       ruleSet,
		ruleEvaluator: NewRuleEvaluator(inspector.NewInspectors()),
	}
}

func (w *waf) Inspect(data inspector.InspectData) ([]DetectionEvent, error) {
	var detectionEvents []DetectionEvent

	for _, r := range w.ruleSet.Rules {
		results, doBlock := w.ruleEvaluator.Eval(r, data)

		for _, result := range results {
			detectionEvents = append(detectionEvents, NewDetectionEvent(data.WafOperationContext, *result))
		}

		if doBlock {
			return detectionEvents, &SecurityBlockingError{}
		}
	}

	return detectionEvents, nil
}
