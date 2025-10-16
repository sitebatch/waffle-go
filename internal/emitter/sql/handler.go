package sql

import (
	"context"

	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type SQLOperation struct {
	operation.Operation

	*waf.WafOperation
}

type SQLOperationArg struct {
	Query string
}

type SQLOperationResult struct {
	BlockErr error
}

func (SQLOperationArg) IsArgOf(*SQLOperation)        {}
func (*SQLOperationResult) IsResultOf(*SQLOperation) {}

func (r *SQLOperationResult) IsBlock() bool {
	return r.BlockErr != nil
}

func ProtectSQLOperation(ctx context.Context, query string) error {
	parent, _ := operation.FindOperationFromContext(ctx)
	if parent == nil {
		return nil
	}

	var wafop *waf.WafOperation
	if parentOp, ok := parent.(*http.HTTPRequestHandlerOperation); ok {
		wafop = parentOp.WafOperation
	} else {
		wafop, _ = waf.InitializeWafOperation(ctx)
	}

	op := &SQLOperation{
		Operation:    operation.NewOperation(parent),
		WafOperation: wafop,
	}

	operation.StartOperation(
		op, SQLOperationArg{Query: query},
	)

	res := &SQLOperationResult{}
	operation.FinishOperation(op, res)

	if res.IsBlock() {
		return res.BlockErr
	}

	return nil
}
