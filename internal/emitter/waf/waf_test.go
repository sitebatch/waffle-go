package waf_test

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/stretchr/testify/assert"
)

func TestWAF_Inspect(t *testing.T) {
	t.Parallel()

	r := &rule.RuleSet{
		Version: "1.0",
		Rules: []rule.Rule{
			{
				ID: "1",
				Conditions: []rule.Condition{
					{
						Inspector: "regex",
						InspectTarget: []rule.InspectTarget{
							{
								Target: "http.request.header",
								Keys:   []string{"User-Agent"},
							},
						},
						Regex: "BadBot",
					},
				},
				Action: "monitor",
			},
			{
				ID: "2",
				Conditions: []rule.Condition{
					{
						Inspector: "regex",
						InspectTarget: []rule.InspectTarget{
							{
								Target: "http.request.header",
								Keys:   []string{"User-Agent"},
							},
						},
						Regex: "EvilBot",
					},
				},
				Action: "block",
			},
		},
	}

	w := waf.NewWAF(r)

	ctx := wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
		URL:      "http://example.com",
		Headers:  map[string][]string{"User-Agent": {"Go-http-client/1.1"}},
		Body:     map[string][]string{"key": {"value"}},
		ClientIP: "127.0.0.1",
	}))

	testCases := map[string]struct {
		data                inspector.InspectData
		wantDetectionEvents []waf.DetectionEvent
		wantError           error
	}{
		"no match": {
			data: *inspector.NewInspectDataBuilder(ctx).WithHTTPRequestHeader(http.Header{
				"User-Agent": []string{"Go-http-client/1.1"},
			}).Build(),
			wantDetectionEvents: nil,
			wantError:           nil,
		},
		"match": {
			data: *inspector.NewInspectDataBuilder(ctx).WithHTTPRequestHeader(http.Header{
				"User-Agent": []string{"BadBot"},
			}).Build(),
			wantDetectionEvents: []waf.DetectionEvent{
				waf.NewDetectionEvent(ctx, waf.EvalResult{
					Rule:      r.Rules[0],
					InspectBy: "regex",
					InspectResult: &inspector.InspectResult{
						Target:  inspector.InspectTargetHttpRequestHeader,
						Message: "Suspicious pattern detected: 'BadBot' matches regex 'BadBot'",
						Payload: "BadBot",
					},
				}),
			},
			wantError: nil,
		},
		"when match, should return block error if action is block": {
			data: *inspector.NewInspectDataBuilder(ctx).WithHTTPRequestHeader(http.Header{
				"User-Agent": []string{"EvilBot"},
			}).Build(),
			wantDetectionEvents: []waf.DetectionEvent{
				waf.NewDetectionEvent(ctx, waf.EvalResult{
					Rule:      r.Rules[1],
					InspectBy: "regex",
					InspectResult: &inspector.InspectResult{
						Target:  inspector.InspectTargetHttpRequestHeader,
						Message: "Suspicious pattern detected: 'EvilBot' matches regex 'EvilBot'",
						Payload: "EvilBot",
					},
				}),
			},
			wantError: &action.BlockError{
				RuleID:    "2",
				Inspector: "regex",
			},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			detectionEvents, err := w.Inspect(tt.data)

			assert.Equal(t, tt.wantError, err)

			opt := cmpopts.IgnoreFields(waf.DetectionEvent{}, "DetectedAt")
			if diff := cmp.Diff(tt.wantDetectionEvents, detectionEvents, opt); diff != "" {
				t.Errorf("detectionEvents (-want +got):\n%s", diff)
			}
		})
	}
}
