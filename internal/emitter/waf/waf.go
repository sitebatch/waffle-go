package waf

import (
	"sync"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type WAF interface {
	Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]DetectionEvent, error)
}

type waf struct {
	rules         *rule.RuleSet
	ruleEvaluator *RuleEvaluator

	inspectors map[string]inspector.Inspector

	mu sync.Mutex
}

func NewWAF(rules *rule.RuleSet) WAF {
	inspectors := make(map[string]inspector.Inspector)
	for n, i := range inspector.NewInspector() {
		inspectors[n] = i
	}

	return &waf{
		rules:         rules,
		ruleEvaluator: NewRuleEvaluator(inspectors),
	}
}

func (w *waf) Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]DetectionEvent, error) {
	detectionEvents := make([]DetectionEvent, 0)

	for _, rule := range w.rules.Rules {
		results, doBlock := w.ruleEvaluator.Eval(wafOpCtx, rule, data)

		for _, result := range results {
			event := NewDetectionEvent(
				wafOpCtx,
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
