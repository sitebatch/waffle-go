package waf

import (
	"errors"
	"sync"

	"github.com/sitebatch/waffle-go/internal/action"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type detectionResult struct {
	inspector string
	reason    error
}

type ruleConditionResult map[string]detectionResult
type DetectionEvents map[string]ruleConditionResult

type WAF interface {
	RegisterInspector(name string, inspector inspector.Inspector)
	Inspect(data inspector.InspectData) error
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
func (w *waf) Inspect(data inspector.InspectData) error {
	for _, rule := range w.rules.Rules {
		if err := w.inspect(rule, data); err != nil {
			return err
		}
	}
	return nil
}

func (w *waf) handleAction(rule rule.Rule, inspector string, detectionErr *action.DetectionError) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.addDetectionEvent(rule.ID, inspector, detectionErr)
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

func (w *waf) addDetectionEvent(ruleID, inspector string, reason error) {
	if _, exists := w.detectionEvents[ruleID]; !exists {
		w.detectionEvents[ruleID] = ruleConditionResult{}
	}

	w.detectionEvents[ruleID][inspector] = detectionResult{
		inspector: inspector,
		reason:    reason,
	}
}

func (w *waf) inspect(rule rule.Rule, data inspector.InspectData) error {
	for _, condition := range rule.Conditions {
		if err := w.inspectCondition(rule, condition, data); err != nil {
			return err
		}
	}
	return nil
}

func (w *waf) inspectCondition(rule rule.Rule, condition rule.Condition, data inspector.InspectData) error {
	for _, target := range condition.InspectTarget {
		if !data.HasTarget(inspector.InspectTarget(target.Target)) {
			continue
		}

		if i, exists := w.inspectors[condition.Inspector]; exists {
			if err := w.doInspect(i, data, condition); err != nil {
				var detectionErr *action.DetectionError
				if errors.As(err, &detectionErr) {
					if err := w.handleAction(rule, condition.Inspector, detectionErr); err != nil {
						return err
					}
				} else {
					log.Error("Error while inspecting", "error", err)
				}
			}
		}
	}
	return nil
}

func (w *waf) doInspect(i inspector.Inspector, data inspector.InspectData, condition rule.Condition) error {
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

	default:
		log.Warn("Unknown inspector", "name", i.Name())
		return i.Inspect(data, nil)
	}
}
