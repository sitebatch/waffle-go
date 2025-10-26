package rule

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/sitebatch/waffle-go/internal/rule/validator"
)

//go:embed rules.json
var defaultRuleSetJSON []byte

var LoadedRuleSet = defaultRuleSetValue()

type RuleSet struct {
	Version string
	Rules   []Rule
}

type Rule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Tags       []string    `json:"tags"`
	Action     string      `json:"action"`
	Conditions []Condition `json:"conditions"`
}

type InspectTarget struct {
	Target string   `json:"target"`
	Keys   []string `json:"keys"`
}

type Condition struct {
	Inspector     string          `json:"inspector"`
	InspectTarget []InspectTarget `json:"inspect_target"`

	Regex     string   `json:"regex,omitempty"`
	MatchList []string `json:"match_list,omitempty"`

	Threshold float64 `json:"threshold,omitempty"`
}

func defaultRuleSetValue() *atomic.Value {
	v := &atomic.Value{}
	v.Store(&RuleSet{})
	return v
}

func DefaultRuleSetJSON() []byte {
	return defaultRuleSetJSON
}

func GetRuleSet() *RuleSet {
	return LoadedRuleSet.Load().(*RuleSet)
}

func LoadRuleSet(jsonRuleSet []byte) error {
	var ruleSet *RuleSet
	if err := json.Unmarshal(jsonRuleSet, &ruleSet); err != nil {
		return err
	}

	if err := ruleSet.Validate(); err != nil {
		return err
	}

	LoadedRuleSet.Store(ruleSet)

	return nil
}

func (r Rule) IsBlockAction() bool {
	return r.Action == "block"
}

func (r RuleSet) Validate() error {
	for _, rule := range r.Rules {
		if err := r.validateDuplecatedRuleID(rule.ID); err != nil {
			return err
		}

		if err := rule.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (r RuleSet) validateDuplecatedRuleID(ruleID string) error {
	count := 0

	for _, rule := range r.Rules {
		if rule.ID == ruleID {
			count++
		}

		if count > 1 {
			return fmt.Errorf("duplicated rule id %s", ruleID)
		}
	}

	return nil
}

func (r Rule) validate() error {
	if err := r.validateAction(); err != nil {
		return err
	}

	if err := r.validateCondition(); err != nil {
		return err
	}

	return nil
}

func (r Rule) validateAction() error {
	if r.Action == "" {
		return fmt.Errorf("action is required")
	}

	if r.Action != "block" && r.Action != "monitor" {
		return fmt.Errorf("invalid action %s", r.Action)
	}

	return nil
}

func (r Rule) validateCondition() error {
	if len(r.Conditions) == 0 {
		return fmt.Errorf("conditions are required")
	}

	for _, condition := range r.Conditions {
		if err := condition.validateCondition(); err != nil {
			return err
		}

		if len(condition.InspectTarget) == 0 {
			return fmt.Errorf("inspect_target is required")
		}

		for _, target := range condition.InspectTarget {
			if err := target.validateInspectTarget(condition.Inspector); err != nil {
				return err
			}
		}
	}

	return nil
}

func (t InspectTarget) validateInspectTarget(inspectorName string) error {
	if t.Target == "" {
		return fmt.Errorf("target is required")
	}

	if err := validator.ValidateInspector(inspectorName, t.Target); err != nil {
		return err
	}

	return nil
}

func (c Condition) validateCondition() error {
	if c.Inspector == "" {
		return fmt.Errorf("inspector is required")
	}

	if err := c.validateRegex(); err != nil {
		return err
	}

	return nil
}

func (c Condition) validateRegex() error {
	if c.Inspector == "regex" && c.Regex == "" {
		return fmt.Errorf("regex is required")
	}

	return nil
}
