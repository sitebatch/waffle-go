package waf

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/log"
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

type Option func(*WafOperation)

func NewWafOperation(parent operation.Operation, waf WAF, wafOpCtx *wafcontext.WafOperationContext) *WafOperation {
	return &WafOperation{
		Operation:           operation.NewOperation(parent),
		Waf:                 waf,
		wafOperationContext: wafOpCtx,
	}
}

func WithHttpRequstContext(req wafcontext.HttpRequest) Option {
	return func(o *WafOperation) {
		if o.wafOperationContext == nil {
			o.wafOperationContext = wafcontext.NewWafOperationContext()
		}

		o.wafOperationContext.WithWafOperationContext(wafcontext.WithHttpRequstContext(req))
	}
}

// InitializeWafOperation initializes a WAF operation and sets it in the context.
// The returned context contains the initialized WAF operation.
func InitializeWafOperation(ctx context.Context, opts ...Option) (*WafOperation, context.Context) {
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
	events, err := wafOp.Waf.Inspect(wafOp.OperationContext(), inspectData)
	if err != nil {
		var blockError *action.BlockError
		if errors.As(err, &blockError) {
			wafOp.blockErr = blockError
			wafOp.log("block", fmt.Sprintf("Threat blocked: %s", blockError.Error()), blockError.RuleID, blockError.Inspector)
			return
		}

		log.Error("failed to inspect", "error", err)
	}

	wafOp.snapshot(op, events)
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
	if err := GetExporter().Export(context.Background(), events); err != nil {
		log.Error("failed to export WAF event", "error", err)
	}
	wafOp.eventRecorder.Clear()
}

// SetMeta sets metadata to the WAF operation context.
func (wafOp *WafOperation) SetMeta(key string, value string) {
	wafOp.wafOperationContext.SetMeta(key, value)
}

// OperationContext returns the WAF operation context.
func (wafOp *WafOperation) OperationContext() *wafcontext.WafOperationContext {
	return wafOp.wafOperationContext
}

func (wafOp *WafOperation) log(action string, msg string, ruleID string, inspector string) {
	var clientIP string
	var url string

	if wafOp.wafOperationContext != nil && wafOp.wafOperationContext.GetHttpRequest() != nil {
		clientIP = wafOp.wafOperationContext.GetHttpRequest().ClientIP
		url = wafOp.wafOperationContext.GetHttpRequest().URL
	}

	if wafOp.wafOperationContext != nil && wafOp.wafOperationContext.GetMeta() != nil {
		meta := wafOp.wafOperationContext.GetMeta()
		if userID, ok := meta["UserID"]; ok {
			log.Info("user", "userID", userID)
		}
	}

	switch action {
	case "block":
		log.Info(msg, "ruleID", ruleID, "inspector", inspector, "clientIP", clientIP, "url", url)
	case "detect":
		log.Info(msg, "ruleID", ruleID, "inspector", inspector, "clientIP", clientIP, "url", url)
	default:
		log.Error("unknown action", "action", action)
	}
}

func (wafOp *WafOperation) snapshot(op operation.Operation, events []DetectionEvent) {
	wafOp.mu.Lock()
	defer wafOp.mu.Unlock()

	s := &snapshot{
		events:    events,
		operation: op,
	}

	wafOp.eventRecorder.Store(s)
}
