package os

import (
	"context"

	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type FileOperation struct {
	operation.Operation

	*waf.WafOperation
}

type FileOperationArg struct {
	Path string
}

type FileOperationResult struct {
	BlockErr error
}

func (FileOperationArg) IsArgOf(*FileOperation)        {}
func (*FileOperationResult) IsResultOf(*FileOperation) {}

func (r *FileOperationResult) IsBlock() bool {
	return r.BlockErr != nil
}

func ProtectFileOperation(ctx context.Context, path string) error {
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

	op := &FileOperation{
		Operation:    operation.NewOperation(parent),
		WafOperation: wafop,
	}

	operation.StartOperation(
		op, FileOperationArg{Path: path},
	)

	res := &FileOperationResult{}
	operation.FinishOperation(op, res)

	if res.BlockErr != nil {
		return res.BlockErr
	}

	return nil
}
