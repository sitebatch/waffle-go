package account_takeover

import (
	"context"

	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type ProtectLoginOperation struct {
	operation.Operation

	*waf.WafOperation
}

type ProtectLoginOperationArg struct {
	ClientIP string
	UserID   string
}

type ProtectLoginOperationResult struct {
	BlockErr error
}

func (ProtectLoginOperationArg) IsArgOf(*ProtectLoginOperation)        {}
func (*ProtectLoginOperationResult) IsResultOf(*ProtectLoginOperation) {}

func (r *ProtectLoginOperationResult) IsBlock() bool {
	return r.BlockErr != nil
}

func IsSuspiciousLoginActivity(
	ctx context.Context,
	clientIP string,
	userID string,
) error {
	parent, _ := operation.FindOperationFromContext(ctx)
	if parent == nil {
		parent = operation.NewOperation(nil)
	}

	var wafop *waf.WafOperation
	if parentOp, ok := parent.(*http.HTTPRequestHandlerOperation); ok {
		wafop = parentOp.WafOperation
	} else {
		wafop, _ = waf.InitializeWafOperation(ctx)
	}

	op := &ProtectLoginOperation{
		Operation:    operation.NewOperation(parent),
		WafOperation: wafop,
	}

	operation.StartOperation(
		op, ProtectLoginOperationArg{ClientIP: clientIP, UserID: userID},
	)

	res := &ProtectLoginOperationResult{}
	operation.FinishOperation(op, res)

	if res.BlockErr != nil {
		return res.BlockErr
	}

	return nil
}
