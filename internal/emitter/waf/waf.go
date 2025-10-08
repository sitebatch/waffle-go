package waf

import (
	"sync"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/rule"
	"golang.org/x/time/rate"
)

type ruleConditionResult map[string]action.DetectionEvent
type DetectionEvents map[string]ruleConditionResult

type WAF interface {
	RegisterInspector(name string, inspector inspector.Inspector)
	Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) error
	GetDetectionEvents() DetectionEvents
}

type waf struct {
	rules      *rule.RuleSet
	inspectors map[string]inspector.Inspector

	detectionEvents DetectionEvents
	blocked         bool

	mu sync.Mutex
}

func NewWAF(rules *rule.RuleSet) WAF {
	detectionEvents := make(DetectionEvents)
	for _, rule := range rules.Rules {
		conditionResult := ruleConditionResult{}
		if _, exists := detectionEvents[rule.ID]; !exists {
			detectionEvents[rule.ID] = conditionResult
		}
	}

	waf := &waf{
		rules:           rules,
		inspectors:      make(map[string]inspector.Inspector),
		detectionEvents: detectionEvents,
		blocked:         false,
	}

	for n, i := range inspector.NewInspector() {
		waf.RegisterInspector(n, i)
	}

	return waf
}

func (w *waf) RegisterInspector(name string, inspector inspector.Inspector) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inspectors[name] = inspector
}

func (w *waf) GetDetectionEvents() DetectionEvents {
	return w.detectionEvents
}

// Inspect checks the data against the rules and returns an error if the data is blocked.
func (w *waf) Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) error {
	for _, rule := range w.rules.Rules {
		if err := w.inspect(wafOpCtx, rule, data); err != nil {
			return err
		}
	}
	return nil
}

func (w *waf) handleAction(wafOpCtx *wafcontext.WafOperationContext, rule rule.Rule, inspector string, suspicious *inspector.SuspiciousResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.addDetectionEvent(wafOpCtx, rule.ID, inspector, suspicious)
	if len(w.detectionEvents[rule.ID]) != len(rule.Conditions) {
		return nil
	}

	if !rule.IsBlockAction() {
		return nil
	}

	w.blocked = true
	return &action.BlockError{
		RuleID:    rule.ID,
		Inspector: inspector,
	}
}

func (w *waf) addDetectionEvent(wafOpCtx *wafcontext.WafOperationContext, ruleID, inspector string, suspicious *inspector.SuspiciousResult) {
	if _, exists := w.detectionEvents[ruleID]; !exists {
		w.detectionEvents[ruleID] = ruleConditionResult{}
	}

	detectionContext := &action.DetectionContext{}
	if wafOpCtx.Meta != nil {
		detectionContext.Meta = wafOpCtx.Meta
	}

	if wafOpCtx.HttpRequest != nil {
		detectionContext.HttpRequest = &action.HttpRequest{
			URL:      wafOpCtx.HttpRequest.URL,
			Headers:  wafOpCtx.HttpRequest.Headers,
			Body:     wafOpCtx.HttpRequest.Body,
			ClientIP: wafOpCtx.HttpRequest.ClientIP,
		}
	}

	event := action.NewDeetectionEvent(
		ruleID,
		inspector,
		suspicious.Message,
		suspicious.Payload,
		detectionContext,
	)

	w.detectionEvents[ruleID][inspector] = event
}

func (w *waf) inspect(wafOpCtx *wafcontext.WafOperationContext, rule rule.Rule, data inspector.InspectData) error {
	for _, condition := range rule.Conditions {
		if err := w.inspectCondition(wafOpCtx, rule, condition, data); err != nil {
			return err
		}
	}
	return nil
}

func (w *waf) inspectCondition(wafOpCtx *wafcontext.WafOperationContext, rule rule.Rule, condition rule.Condition, data inspector.InspectData) error {
	for _, target := range condition.InspectTarget {
		if !data.HasTarget(inspector.InspectTarget(target.Target)) {
			continue
		}

		if i, exists := w.inspectors[condition.Inspector]; exists {
			suspicious, err := w.doInspect(i, data, condition)
			if err != nil {
				log.Error("Error while inspecting", "error", err)
				continue
			}

			if suspicious != nil {
				if err := w.handleAction(wafOpCtx, rule, condition.Inspector, suspicious); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (w *waf) doInspect(i inspector.Inspector, data inspector.InspectData, condition rule.Condition) (*inspector.SuspiciousResult, error) {
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
