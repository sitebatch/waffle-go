package waf

import (
	"context"
	"errors"
	"sync"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
)

// WafOperation is an operation that represents a WAF inspection process.
type WafOperation struct {
	operation.Operation

	Waf                 WAF
	wafOperationContext *wafcontext.WafOperationContext

	eventRecorder *EventRecorder
	blockErr      *action.BlockError

	mu sync.Mutex
}

type WafOperationArg struct{}
type WafOperationResult struct {
	BlockErr        *action.BlockError
	DetectionEvents []DetectionEvent
}

func (WafOperationArg) IsArgOf(*WafOperation)       {}
func (WafOperationResult) IsResultOf(*WafOperation) {}

func (r *WafOperationResult) IsBlock() bool {
	return r.BlockErr != nil
}

type WafOperationContextOption func(*WafOperation)

func WithHttpRequstContext(req wafcontext.HttpRequest) WafOperationContextOption {
	return func(o *WafOperation) {
		if o.wafOperationContext == nil {
			o.wafOperationContext = wafcontext.NewWafOperationContext()
		}

		o.wafOperationContext.WithWafOperationContext(wafcontext.WithHttpRequstContext(req))
	}
}

func NewWafOperation(parent operation.Operation, waf WAF, wafOpCtx *wafcontext.WafOperationContext) *WafOperation {
	return &WafOperation{
		Operation:           operation.NewOperation(parent),
		Waf:                 waf,
		eventRecorder:       NewEventRecorder(),
		wafOperationContext: wafOpCtx,
	}
}

// InitializeWafOperation initializes a WAF operation and sets it in the context.
// The returned context contains the initialized WAF operation.
func InitializeWafOperation(ctx context.Context, opts ...WafOperationContextOption) (*WafOperation, context.Context) {
	parent, _ := operation.FindOperationFromContext(ctx)
	wafCtx := wafcontext.NewWafOperationContext()
	op := NewWafOperation(parent, NewWAF(rule.LoadedRule), wafCtx)

	for _, opt := range opts {
		opt(op)
	}

	return op, operation.SetOperation(ctx, op)
}

// Run inspects the request data and blocks the request if it violates the WAF rules.
func (wafOp *WafOperation) Run(op operation.Operation, inspectData inspector.InspectData) {
	events, err := wafOp.Waf.Inspect(inspectData)

	wafOp.mu.Lock()
	defer wafOp.mu.Unlock()

	if len(events) > 0 {
		wafOp.snapshot(op, events)
	}

	if err != nil {
		var blockError *action.BlockError
		if errors.As(err, &blockError) {
			wafOp.blockErr = blockError
			return
		}

		handler.GetErrorHandler().HandleError(err)
	}
}

// IsBlock returns true if the request should be blocked.
func (wafOp *WafOperation) IsBlock() bool {
	return wafOp.blockErr != nil
}

// FinishInspect finishes the inspection and sets the result.
func (wafOp *WafOperation) FinishInspect(op operation.Operation, res *WafOperationResult) {
	wafOp.mu.Lock()
	defer wafOp.mu.Unlock()

	res.BlockErr = wafOp.blockErr

	events := wafOp.eventRecorder.Load()

	if events != nil {
		res.DetectionEvents = events.Events()

		if err := GetExporter().Export(context.Background(), events); err != nil {
			handler.GetErrorHandler().HandleError(err)
		}

		wafOp.eventRecorder.Clear()
	}
}

// SetMeta sets metadata to the WAF operation context.
func (wafOp *WafOperation) SetMeta(key string, value string) {
	wafOp.mu.Lock()
	defer wafOp.mu.Unlock()

	wafOp.wafOperationContext.SetMeta(key, value)
}

// OperationContext returns the WAF operation context.
func (wafOp *WafOperation) OperationContext() *wafcontext.WafOperationContext {
	return wafOp.wafOperationContext
}

func (wafOp *WafOperation) snapshot(op operation.Operation, events []DetectionEvent) {
	s := &snapshot{
		events:    events,
		operation: op,
	}

	wafOp.eventRecorder.Store(s)
}

func (wafOp *WafOperation) DetectionEvents() ReadOnlyDetectionEvents {
	return wafOp.eventRecorder.Load()
}
