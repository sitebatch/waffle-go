package waf_test

import (
	"fmt"
	"testing"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/stretchr/testify/assert"
)

type mockWaf struct {
	mockInspectFunc        func(data inspector.InspectData) error
	mockGetDetectionEvents func() waf.DetectionEvents
}

func (w *mockWaf) RegisterInspector(name string, inspector inspector.Inspector) {}

func (w *mockWaf) Inspect(data inspector.InspectData) error {
	return w.mockInspectFunc(data)
}

func (w *mockWaf) GetDetectionEvents() waf.DetectionEvents {
	return w.mockGetDetectionEvents()
}

func TestSetMeta(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		op   *waf.WafOperation
		want map[string]string
	}{
		"can set Metadata in Operation": {
			op: &waf.WafOperation{
				Operation: operation.NewOperation(nil),
				WafOperationContext: &waf.WafOperationContext{
					HttpRequest: &waf.HttpRequest{},
				},
			},
			want: map[string]string{"key": "value"},
		},
		"can set Metadata in Operation when waf operation context is nil": {
			op: &waf.WafOperation{
				Operation: operation.NewOperation(nil),
			},
			want: map[string]string{"key": "value"},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tt.op.SetMeta("key", "value")
			assert.Equal(t, tt.want, tt.op.OperationContext().Meta)
		})
	}
}

func TestWafOperation_Run(t *testing.T) {
	t.Parallel()

	op := &http.HTTPRequestHandlerOperation{
		Operation: operation.NewOperation(nil),
	}

	type arrange struct {
		mockInspectFunc        func(data inspector.InspectData) error
		mockGetDetectionEvents func() waf.DetectionEvents
	}

	testCases := map[string]struct {
		arrange arrange
		block   bool
	}{
		"when inspector return block error, set block on waf operation": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) error {
					return &action.BlockError{RuleID: "example-rule", Inspector: string(inspector.RegexInspectorName)}
				},
				mockGetDetectionEvents: func() waf.DetectionEvents {
					return waf.DetectionEvents{}
				},
			},
			block: true,
		},
		"when inspector return nil (not detected)": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) error {
					return nil
				},
				mockGetDetectionEvents: func() waf.DetectionEvents {
					return waf.DetectionEvents{}
				},
			},
			block: false,
		},
		"when inspector return error (not blocked error)": {
			arrange: arrange{
				mockInspectFunc: func(data inspector.InspectData) error {
					return fmt.Errorf("something error")
				},
				mockGetDetectionEvents: func() waf.DetectionEvents {
					return waf.DetectionEvents{}
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
				Target: inspector.NewInspectDataBuilder().Target,
			})

			assert.Equal(t, tt.block, wafop.IsBlock())
		})
	}
}
