package waf

import (
	"context"
	"errors"
	"fmt"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
)

// WafOperation is an operation that inspects the request data and blocks the request if it violates the WAF rules.
type WafOperation struct {
	operation.Operation
	Waf WAF

	wafOperationContext *WafOperationContext
	blockErr            *action.BlockError
}

type WafOperationArg struct{}
type WafOperationResult struct {
	BlockErr        *action.BlockError
	DetectionEvents DetectionEvents
}

type WafOperationContext struct {
	URL      string
	ClientIP string
}

func (WafOperationArg) IsArgOf(*WafOperation)       {}
func (WafOperationResult) IsResultOf(*WafOperation) {}

func (r *WafOperationResult) IsBlock() bool {
	return r.BlockErr != nil
}

type Option func(*WafOperation)

func WithOperationContext(w WafOperationContext) Option {
	return func(o *WafOperation) {
		o.wafOperationContext = &w
	}
}

// StartWafOperation creates a new WafOperation and returns it with the context.
// This operation should be created at the top level of processing HTTP requests and propagated to subsequent processing.
func StartWafOperation(ctx context.Context, opts ...Option) (*WafOperation, context.Context) {
	if !operation.IsRootOperationInitialized() {
		panic("waffle is not initialized, forgot to call waffle.Start()?")
	}

	parent, _ := operation.FindOperationFromContext(ctx)

	op := &WafOperation{
		Operation: operation.NewOperation(parent),
		Waf:       NewWAF(rule.LoadedRule),
	}

	for _, opt := range opts {
		opt(op)
	}

	return op, operation.StartAndRegisterOperation(ctx, op, WafOperationArg{})
}

// Run inspects the request data and blocks the request if it violates the WAF rules.
func (wafOp *WafOperation) Run(op operation.Operation, inspectData inspector.InspectData) {
	err := wafOp.Waf.Inspect(inspectData)
	if err != nil {
		var blockError *action.BlockError
		if errors.As(err, &blockError) {
			wafOp.blockErr = blockError
			wafOp.log("block", fmt.Sprintf("Threat blocked: %s", blockError.Error()), blockError.RuleID, blockError.Inspector)
			return
		}

		log.Error("failed to inspect", "error", err)
	}

	for ruleID, event := range wafOp.Waf.GetDetectionEvents() {
		for inspector, result := range event {
			wafOp.log("detect", fmt.Sprintf("Threat detected: %s", result.reason.Error()), ruleID, inspector)
		}
	}
}

// IsBlock returns true if the request should be blocked.
func (wafOp *WafOperation) IsBlock() bool {
	return wafOp.blockErr != nil
}

// FinishInspect finishes the inspection and sets the result.
func (wafOp *WafOperation) FinishInspect(res *WafOperationResult) {
	res.BlockErr = wafOp.blockErr
	res.DetectionEvents = wafOp.Waf.GetDetectionEvents()
}

func (wafOp *WafOperation) log(action string, msg string, ruleID string, inspector string) {
	var clientIP string
	var url string

	if wafOp.wafOperationContext != nil {
		clientIP = wafOp.wafOperationContext.ClientIP
		url = wafOp.wafOperationContext.URL
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
