package waf_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ waf.WAF = (*mockWaf)(nil)

type mockWaf struct {
	mockInspectFunc func(data inspector.InspectData) ([]waf.DetectionEvent, error)
}

func (w *mockWaf) Inspect(data inspector.InspectData) ([]waf.DetectionEvent, error) {
	return w.mockInspectFunc(data)
}

func TestInitializeWafOperation(t *testing.T) {
	t.Parallel()

	require.NoError(t, rule.LoadDefaultRules())

	testCases := map[string]struct {
		opts                 []waf.WafOperationContextOption
		wantOperationContext *wafcontext.WafOperationContext
	}{
		"can initialize WafOperation without options": {
			opts:                 nil,
			wantOperationContext: wafcontext.NewWafOperationContext(),
		},
		"can initialize WafOperation with HTTP request context": {
			opts: []waf.WafOperationContextOption{
				waf.WithHttpRequstContext(wafcontext.HttpRequest{
					URL:      "http://example.com",
					Headers:  map[string][]string{"User-Agent": {"Go-http-client/1.1"}},
					Body:     map[string][]string{"key": {"value"}},
					ClientIP: "127.0.0.1",
				}),
			},
			wantOperationContext: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(
				wafcontext.HttpRequest{
					URL:      "http://example.com",
					Headers:  map[string][]string{"User-Agent": {"Go-http-client/1.1"}},
					Body:     map[string][]string{"key": {"value"}},
					ClientIP: "127.0.0.1",
				},
			)),
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootOp := operation.NewRootOperation()
			operation.InitRootOperation(rootOp)

			op := &http.HTTPRequestHandlerOperation{
				Operation: operation.NewOperation(nil),
			}
			ctx := operation.SetOperation(context.Background(), op)

			wafOp, ctx := waf.InitializeWafOperation(ctx, tt.opts...)

			got, found := operation.FindOperation[waf.WafOperation](ctx)
			assert.True(t, found)
			assert.Equal(t, wafOp, got)

			assert.Equal(t, tt.wantOperationContext, wafOp.OperationContext())
		})
	}
}

func TestSetMeta(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		op   *waf.WafOperation
		want map[string]string
	}{
		"can set Metadata in Operation": {
			op: waf.NewWafOperation(
				operation.NewOperation(nil),
				nil,
				wafcontext.NewWafOperationContext(),
			),
			want: map[string]string{"key": "value"},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tt.op.SetMeta("key", "value")
			assert.Equal(t, tt.want, tt.op.OperationContext().GetMeta())
		})
	}
}

func TestWafOperation_Run(t *testing.T) {
	t.Parallel()

	type arrange struct {
		mockInspectFunc func(data inspector.InspectData) ([]waf.DetectionEvent, error)
	}

	wafOpCtx := wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(
		wafcontext.HttpRequest{
			URL:      "http://example.com",
			Headers:  map[string][]string{"User-Agent": {"Go-http-client/1.1"}},
			Body:     map[string][]string{"key": {"value"}},
			ClientIP: "127.0.0.1",
		},
	))

	testCases := map[string]struct {
		arrange                arrange
		wantDetectionEventSize int
		block                  bool
	}{
		"when inspector return block error, set block on waf operation": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return []waf.DetectionEvent{
							waf.NewDetectionEvent(data.WafOperationContext, waf.EvalResult{
								Rule: rule.Rule{
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
									Action: "block",
								},
								InspectBy: "regex",
								InspectResult: &inspector.InspectResult{
									Target:  inspector.InspectTargetHttpRequestHeader,
									Message: "Suspicious pattern detected: 'BadBot' matches regex 'BadBot'",
									Payload: "BadBot",
								},
							}),
						}, &action.BlockError{
							RuleID:    "1",
							Inspector: "regex",
						}
				},
			},
			wantDetectionEventSize: 1,
			block:                  true,
		},
		"when inspector return nil (not detected)": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return nil, nil
				},
			},
			wantDetectionEventSize: 0,
			block:                  false,
		},
		"when inspector return error (not blocked error)": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return nil, assert.AnError
				},
			},
			wantDetectionEventSize: 0,
			block:                  false,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := &http.HTTPRequestHandlerOperation{
				Operation: operation.NewOperation(nil),
			}

			wafop := waf.NewWafOperation(op, &mockWaf{
				mockInspectFunc: tt.arrange.mockInspectFunc,
			}, wafOpCtx)

			wafop.Run(op, inspector.InspectData{
				Target: inspector.NewInspectDataBuilder(wafop.OperationContext()).Target,
			})

			assert.Equal(t, tt.block, wafop.IsBlock())

			evt := wafop.DetectionEvents()
			if tt.wantDetectionEventSize == 0 {
				assert.Nil(t, evt)
			} else {
				assert.Len(t, evt.Events(), tt.wantDetectionEventSize)
			}
		})
	}
}

func TestWafOperation_FinishInspect(t *testing.T) {
	t.Parallel()

	type arrange struct {
		mockInspectFunc func(data inspector.InspectData) ([]waf.DetectionEvent, error)
	}

	wafOpCtx := wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(
		wafcontext.HttpRequest{
			URL:      "http://example.com",
			Headers:  map[string][]string{"User-Agent": {"Go-http-client/1.1"}},
			Body:     map[string][]string{"key": {"value"}},
			ClientIP: "127.0.0.1",
		},
	))

	dummyBlockRule := rule.Rule{
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
		Action: "block",
	}

	dummyMonitorRule := rule.Rule{
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
				Regex: "GoodBot",
			},
		},
		Action: "monitor",
	}

	testCases := map[string]struct {
		arrange    arrange
		wantResult *waf.WafOperationResult
	}{
		"when inspector return block error, set block on waf operation": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return []waf.DetectionEvent{
							waf.NewDetectionEvent(data.WafOperationContext, waf.EvalResult{
								Rule:      dummyBlockRule,
								InspectBy: "regex",
								InspectResult: &inspector.InspectResult{
									Target:  inspector.InspectTargetHttpRequestHeader,
									Message: "Suspicious pattern detected: 'BadBot' matches regex 'BadBot'",
									Payload: "BadBot",
								},
							}),
						}, &action.BlockError{
							RuleID:    "1",
							Inspector: "regex",
						}
				},
			},
			wantResult: &waf.WafOperationResult{
				BlockErr: &action.BlockError{
					RuleID:    "1",
					Inspector: "regex",
				},
				DetectionEvents: []waf.DetectionEvent{
					waf.NewDetectionEvent(wafOpCtx, waf.EvalResult{
						Rule:      dummyBlockRule,
						InspectBy: "regex",
						InspectResult: &inspector.InspectResult{
							Target:  inspector.InspectTargetHttpRequestHeader,
							Message: "Suspicious pattern detected: 'BadBot' matches regex 'BadBot'",
							Payload: "BadBot",
						},
					}),
				},
			},
		},
		"when inspector return monitor event, should not block": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return []waf.DetectionEvent{
						waf.NewDetectionEvent(data.WafOperationContext, waf.EvalResult{
							Rule:      dummyMonitorRule,
							InspectBy: "regex",
							InspectResult: &inspector.InspectResult{
								Target:  inspector.InspectTargetHttpRequestHeader,
								Message: "Suspicious pattern detected: 'GoodBot' matches regex 'GoodBot'",
								Payload: "GoodBot",
							},
						}),
					}, nil
				},
			},
			wantResult: &waf.WafOperationResult{
				BlockErr: nil,
				DetectionEvents: []waf.DetectionEvent{
					waf.NewDetectionEvent(wafOpCtx, waf.EvalResult{
						Rule:      dummyMonitorRule,
						InspectBy: "regex",
						InspectResult: &inspector.InspectResult{
							Target:  inspector.InspectTargetHttpRequestHeader,
							Message: "Suspicious pattern detected: 'GoodBot' matches regex 'GoodBot'",
							Payload: "GoodBot",
						},
					}),
				},
			},
		},
		"when inspector return nil (not detected)": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return nil, nil
				},
			},
			wantResult: &waf.WafOperationResult{
				BlockErr:        nil,
				DetectionEvents: nil,
			},
		},
		"when inspector return error (not blocked error)": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return nil, assert.AnError
				},
			},
			wantResult: &waf.WafOperationResult{
				BlockErr:        nil,
				DetectionEvents: nil,
			},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := &http.HTTPRequestHandlerOperation{
				Operation: operation.NewOperation(nil),
			}

			wafop := waf.NewWafOperation(op, &mockWaf{
				mockInspectFunc: tt.arrange.mockInspectFunc,
			}, wafOpCtx)

			wafop.Run(op, *inspector.NewInspectDataBuilder(wafop.OperationContext()).Build())

			if tt.wantResult.BlockErr != nil {
				assert.NotNil(t, wafop.DetectionEvents())
			}

			result := &waf.WafOperationResult{}
			wafop.FinishInspect(op, result)

			opt := cmpopts.IgnoreFields(waf.DetectionEvent{}, "DetectedAt")
			if diff := cmp.Diff(tt.wantResult.DetectionEvents, result.DetectionEvents, opt); diff != "" {
				t.Errorf("mismatch in DetectionEvents (-want +got):\n%s", diff)
			}

			evt := wafop.DetectionEvents()
			assert.Nil(t, evt)
		})
	}
}
