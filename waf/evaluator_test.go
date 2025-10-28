package waf_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/inspector/types"
	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

type MockInspector struct{}

func (m *MockInspector) IsSupportTarget(target inspector.InspectTarget) bool {
	return target == inspector.InspectTargetHttpRequestURL
}

func (m *MockInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) (*inspector.InspectResult, error) {
	_, ok := data.Target[inspector.InspectTargetHttpRequestURL]
	if !ok {
		return nil, nil
	}

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
			wantResult: nil,
			wantBlock:  false,
		},
		"if the target specified in condition is not included in the inspection targets": {
			rule: monitorMaliciousURLRule,
			data: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetClientIP: types.NewStringValue("192.168.1.1"),
				},
			},
			wantResult: nil,
			wantBlock:  false,
		},
		"if there are multiple conditions and only one of them is met, it should not be detected": {
			rule: multipleConditionsRule,
			data: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			wantResult: nil,
			wantBlock:  false,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			evaluator := waf.NewRuleEvaluator(map[inspector.InspectorName]inspector.Inspector{
				"mock": &MockInspector{},
				"nop":  &NopInspector{},
			})

			gotResult, gotBlock := evaluator.Eval(tt.rule, tt.data)
			assert.Equal(t, tt.wantBlock, gotBlock)
			assert.Equal(t, tt.wantResult, gotResult)
		})
	}
}

func TestNewInspectorArgsFromCondition(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		condition rule.Condition
		want      inspector.InspectorArgs
	}{
		"one target": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.url"},
				},
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{
						Target: "http.request.url",
					},
				},
			},
		},
		"one target with key": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.header", Keys: []string{"User-Agent", "Referer"}},
				},
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{Target: "http.request.header", Params: []string{"User-Agent", "Referer"}},
				},
			},
		},
		"multiple targets": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.header"},
					{Target: "http.request.body"},
				},
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{Target: "http.request.header"},
					{Target: "http.request.body"},
				},
			},
		},
		"multiple targets with keys": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.header", Keys: []string{"User-Agent", "Referer"}},
					{Target: "http.request.body"},
				},
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{Target: "http.request.header", Params: []string{"User-Agent", "Referer"}},
					{Target: "http.request.body"},
				},
			},
		},
		"with Regex": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.header", Keys: []string{"User-Agent"}},
				},
				Regex: "^Bot$",
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{Target: "http.request.header", Params: []string{"User-Agent"}},
				},
				RegexInspectorArgs: inspector.RegexInspectorArgs{
					Regex: "^Bot$",
				},
			},
		},
		"with MatchList": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.query"},
				},
				MatchList: []string{"/etc/password"},
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{Target: "http.request.query"},
				},
				MatchListInspectorArgs: inspector.MatchListInspectorArgs{
					List: []string{"/etc/password"},
				},
			},
		},
		"with Threshold": {
			condition: rule.Condition{
				InspectTarget: []rule.InspectTarget{
					{Target: "http.request.query"},
				},
				Threshold: 10,
			},
			want: inspector.InspectorArgs{
				TargetOptions: []inspector.InspectTargetOptions{
					{Target: "http.request.query"},
				},
				AccountTakeoverInspectorArgs: inspector.AccountTakeoverInspectorArgs{
					LoginRateLimitPerSecond: rate.Limit(10),
				},
			},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			got := waf.NewInspectorArgsFromCondition(tt.condition)
			assert.Equal(t, tt.want, got)
		})
	}
}
