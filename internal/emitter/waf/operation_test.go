package waf_test

import (
	"context"
	"testing"

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
	mockInspectFunc func(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]waf.DetectionEvent, error)
}

func (w *mockWaf) Inspect(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]waf.DetectionEvent, error) {
	return w.mockInspectFunc(wafOpCtx, data)
}

func TestInitializeWafOperation(t *testing.T) {
	t.Parallel()

	require.NoError(t, rule.LoadDefaultRules())

	testCases := map[string]struct {
		opts                 []waf.Option
		wantOperationContext *wafcontext.WafOperationContext
	}{
		"can initialize WafOperation without options": {
			opts:                 nil,
			wantOperationContext: wafcontext.NewWafOperationContext(),
		},
		"can initialize WafOperation with HTTP request context": {
			opts: []waf.Option{
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

/*
func TestWafOperation_Run(t *testing.T) {
	t.Parallel()

	op := &http.HTTPRequestHandlerOperation{
		Operation: operation.NewOperation(nil),
	}

	type arrange struct {
		mockInspectFunc        func(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]waf.DetectionEvent, error)
	}

	testCases := map[string]struct {
		arrange arrange
		block   bool
	}{
		"when inspector return block error, set block on waf operation": {
			arrange: arrange{
				mockInspectFunc: func(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) ([]waf.DetectionEvent, error) {
					return []waf.DetectionEvent{
						{RuleID: "example-rule", Inspector: string(inspector.RegexInspectorName)},
					},
				},
			},
			block: true,
		},
		"when inspector return nil (not detected)": {
			arrange: arrange{
				mockInspectFunc: func(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) error {
					return nil
				},
			},
			block: false,
		},
		"when inspector return error (not blocked error)": {
			arrange: arrange{
				mockInspectFunc: func(wafOpCtx *wafcontext.WafOperationContext, data inspector.InspectData) error {
					return fmt.Errorf("something error")
				},
			},
			block: false,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wafop := &waf.WafOperation{
				Operation: operation.NewOperation(op),
				Waf: &mockWaf{
					mockInspectFunc:        tt.arrange.mockInspectFunc,
					mockGetDetectionEvents: tt.arrange.mockGetDetectionEvents,
				},
			}

			wafop.Run(op, inspector.InspectData{
				Target: inspector.NewInspectDataBuilder(wafop.OperationContext()).Target,
			})

			assert.Equal(t, tt.block, wafop.IsBlock())
		})
	}
}

*/
