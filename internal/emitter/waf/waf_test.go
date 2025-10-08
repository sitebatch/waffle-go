package waf_test

import (
	"net/http"
	"testing"

	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
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

func (m *MockInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) (*inspector.SuspiciousResult, error) {
	url := data.Target[inspector.InspectTargetHttpRequestURL].GetValue()
	if url == "http://malicious.com" {
		return &inspector.SuspiciousResult{
			Message: "malicious URL detected",
			Payload: url,
		}, nil
	}
	return nil, nil
}

type NothingInspector struct{}

func (n *NothingInspector) Name() inspector.InspectorName {
	return inspector.InspectorName("nothing")
}

func (n *NothingInspector) IsSupportTarget(target inspector.InspectTarget) bool {
	return true
}

func (n *NothingInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) (*inspector.SuspiciousResult, error) {
	return nil, nil
}

func TestWAF(t *testing.T) {
	t.Parallel()

	type arrange struct {
		rules []rule.Rule
	}

	testCases := map[string]struct {
		arrange     arrange
		wafOpCtx    *wafcontext.WafOperationContext
		inspectData inspector.InspectData
		expectBlock bool
	}{
		"detect with mock inspector": {
			arrange: arrange{
				rules: []rule.Rule{
					{
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
					},
				},
			},
			wafOpCtx: &wafcontext.WafOperationContext{
				Meta: map[string]string{},
				HttpRequest: &wafcontext.HttpRequest{
					URL:      "http://malicious.com",
					Headers:  http.Header{"Host": []string{"malicious.com"}},
					Body:     map[string][]string{},
					ClientIP: "10.0.1.1",
				},
			},
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			expectBlock: true,
		},
		"detect with mock inspector, but monitor": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "1",
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
					},
				},
			},
			wafOpCtx: &wafcontext.WafOperationContext{
				Meta: map[string]string{},
				HttpRequest: &wafcontext.HttpRequest{
					URL:      "http://malicious.com",
					Headers:  http.Header{"Host": []string{"malicious.com"}},
					Body:     map[string][]string{},
					ClientIP: "10.0.1.1",
				},
			},
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			expectBlock: false,
		},
		"when not malicious url, do not detect with mock inspector": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "2",
						Name:   "Detect Malicious URL by Mock Inspector",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "mock",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
							},
						},
					},
				},
			},
			wafOpCtx: &wafcontext.WafOperationContext{
				Meta: map[string]string{},
				HttpRequest: &wafcontext.HttpRequest{
					URL:      "http://example.com",
					Headers:  http.Header{"Host": []string{"example.com"}},
					Body:     map[string][]string{},
					ClientIP: "10.0.1.1",
				},
			},
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://example.com"),
				},
			},
			expectBlock: false,
		},
		"If there are multiple conditions and only one of them is met, it should not be detected": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "3",
						Name:   "Detect Malicious URL",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "mock",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
							},
							{
								Inspector:     "nothing",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
							},
						},
					},
				},
			},
			wafOpCtx: &wafcontext.WafOperationContext{
				Meta: map[string]string{},
				HttpRequest: &wafcontext.HttpRequest{
					URL:      "http://example.com",
					Headers:  http.Header{"Host": []string{"example.com"}},
					Body:     map[string][]string{},
					ClientIP: "10.0.1.1",
				},
			},
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://example.com"),
				},
			},
			expectBlock: false,
		},
		"Integration test: Regex inspector": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "4",
						Name:   "Detect Malicious URL by Regex",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "regex",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
								Regex:         "malicious",
							},
						},
					},
				},
			},
			wafOpCtx: &wafcontext.WafOperationContext{
				Meta: map[string]string{},
				HttpRequest: &wafcontext.HttpRequest{
					URL:      "http://malicious.com",
					Headers:  http.Header{"Host": []string{"malicious.com"}},
					Body:     map[string][]string{},
					ClientIP: "10.0.1.1",
				},
			},
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			expectBlock: true,
		},
		"Integration test: Regex inspector with specify key": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "4",
						Name:   "Detect Malicious URL by Regex",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "regex",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.header", Keys: []string{"Host"}}},
								Regex:         "malicious\\.com",
							},
						},
					},
				},
			},
			wafOpCtx: &wafcontext.WafOperationContext{
				Meta: map[string]string{},
				HttpRequest: &wafcontext.HttpRequest{
					URL:      "http://example.com",
					Headers:  http.Header{"Host": []string{"malicious.com"}},
					Body:     map[string][]string{},
					ClientIP: "10.0.1.1",
				},
			},
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestHeader: types.NewKeyValues(http.Header{
						"Host": []string{"malicious.com"},
					}),
				},
			},
			expectBlock: true,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := &rule.RuleSet{
				Version: "1.0",
				Rules:   tt.arrange.rules,
			}

			w := waf.NewWAF(rules)
			w.RegisterInspector("mock", &MockInspector{})
			w.RegisterInspector("nothing", &NothingInspector{})

			err := w.Inspect(tt.wafOpCtx, tt.inspectData)

			if tt.expectBlock {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
