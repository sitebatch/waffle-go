package waf_test

import (
	"net/http"
	"testing"

	"github.com/sitebatch/waffle-go/internal/action"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
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

func (m *MockInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) error {
	if data.Target[inspector.InspectTargetHttpRequestURL].GetValue() == "http://malicious.com" {
		return &action.DetectionError{Reason: "malicious URL detected"}
	}
	return nil
}

type NothingInspector struct{}

func (n *NothingInspector) Name() inspector.InspectorName {
	return inspector.InspectorName("nothing")
}

func (n *NothingInspector) IsSupportTarget(target inspector.InspectTarget) bool {
	return true
}

func (n *NothingInspector) Inspect(data inspector.InspectData, args inspector.InspectorArgs) error {
	return nil
}

func TestWAF(t *testing.T) {
	t.Parallel()

	type arrange struct {
		rules []rule.Rule
	}

	testCases := map[string]struct {
		arrange     arrange
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
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: inspector.NewInspectTargetValueString("http://malicious.com"),
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
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: inspector.NewInspectTargetValueString("http://malicious.com"),
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
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: inspector.NewInspectTargetValueString("http://example.com"),
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
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: inspector.NewInspectTargetValueString("http://example.com"),
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
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: inspector.NewInspectTargetValueString("http://malicious.com"),
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
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]inspector.InspectTargetValue{
					inspector.InspectTargetHttpRequestHeader: inspector.NewInspectTargetValueKeyValues(http.Header{
						"Host": []string{"malicious.com"},
					}),
				},
			},
			expectBlock: true,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := &rule.RuleSet{
				Version: "1.0",
				Rules:   tt.arrange.rules,
			}

			waf := waf.NewWAF(rules)
			waf.RegisterInspector("mock", &MockInspector{})
			waf.RegisterInspector("nothing", &NothingInspector{})

			err := waf.Inspect(tt.inspectData)

			if tt.expectBlock {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
