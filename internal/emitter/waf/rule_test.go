package waf_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/stretchr/testify/assert"
)

type MockInspector struct{}

func (m *MockInspector) Name() inspector.InspectorName {
	return inspector.InspectorName("mock")
}

func (m *MockInspector) IsSupportTarget(target inspector.InspectTarget) bool {
	return true
}

func (m *MockInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) (*inspector.InspectResult, error) {
	url := data.Target[inspector.InspectTargetHttpRequestURL].GetValue()
	if url == "http://malicious.com" {
		return &inspector.InspectResult{
			Message: "malicious URL detected",
			Payload: url,
		}, nil
	}
	return nil, nil
}

type NopInspector struct{}

func (n *NopInspector) Name() inspector.InspectorName {
	return inspector.InspectorName("nop")
}

func (n *NopInspector) IsSupportTarget(target inspector.InspectTarget) bool {
	return true
}

func (n *NopInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) (*inspector.InspectResult, error) {
	return nil, nil
}

var (
	blockMaliciousURLRule = rule.Rule{
		ID:     "1",
		Name:   "Detect Malicious URL by Mock Inspector",
		Action: "block",
		Conditions: []rule.Condition{
			{
				Inspector: "mock",
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.url"},
				},
			},
		},
	}
	monitorMaliciousURLRule = rule.Rule{
		ID:     "2",
		Name:   "Detect Malicious URL by Mock Inspector",
		Action: "monitor",
		Conditions: []rule.Condition{
			{
				Inspector: "mock",
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.url"},
				},
			},
		},
	}

	multipleConditionsRule = rule.Rule{
		ID:     "3",
		Name:   "Detect Malicious URL and NOP by Mock Inspector",
		Action: "block",
		Conditions: []rule.Condition{
			{
				Inspector: "mock",
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.url"},
				},
			},
			{
				Inspector: "nop",
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.url"},
				},
			},
		},
	}
)

func TestRuleEvaluator_Eval(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rule       rule.Rule
		data       inspector.InspectData
		wantResult []*waf.EvalResult
		wantBlock  bool
	}{
		"detect malicious URL by MockInspector": {
			rule: monitorMaliciousURLRule,
			data: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			wantResult: []*waf.EvalResult{
				{
					Rule:      monitorMaliciousURLRule,
					InspectBy: "mock",
					InspectResult: &inspector.InspectResult{
						Message: "malicious URL detected",
						Payload: "http://malicious.com",
					},
				},
			},
		},
		"detect malicious URL by MockInspector and return block": {
			rule: blockMaliciousURLRule,
			data: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			wantResult: []*waf.EvalResult{
				{
					Rule:      blockMaliciousURLRule,
					InspectBy: "mock",
					InspectResult: &inspector.InspectResult{
						Message: "malicious URL detected",
						Payload: "http://malicious.com",
					},
				},
			},
			wantBlock: true,
		},
		"no detection by MockInspector": {
			rule: monitorMaliciousURLRule,
			data: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://example.com"),
				},
			},
			wantResult: []*waf.EvalResult{},
			wantBlock:  false,
		},
		"if there are multiple conditions and only one of them is met, it should not be detected": {
			rule: multipleConditionsRule,
			data: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			wantResult: []*waf.EvalResult{},
			wantBlock:  false,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			evaluator := waf.NewRuleEvaluator(map[string]inspector.Inspector{
				"mock": &MockInspector{},
				"nop":  &NopInspector{},
			})

			gotResult, gotBlock := evaluator.Eval(nil, tt.rule, tt.data)

			assert.Equal(t, tt.wantBlock, gotBlock)
			assert.Equal(t, tt.wantResult, gotResult)
		})
	}
}
