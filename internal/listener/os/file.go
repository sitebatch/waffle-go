package os

import (
	"github.com/sitebatch/waffle-go/internal/emitter/os"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type FileSecurity struct{}

func (f *FileSecurity) Name() string {
	return "file_security"
}

func NewFileSecurity(rootOp operation.Operation) (listener.Listener, error) {
	fileSec := &FileSecurity{}

	operation.OnStart(rootOp, fileSec.OnOpen)
	operation.OnFinish(rootOp, fileSec.OnFinish)
	return fileSec, nil
}

func (fileSec *FileSecurity) OnOpen(op *os.FileOperation, args os.FileOperationArg) {
	op.Run(op, *inspector.NewInspectDataBuilder(op.OperationContext()).WithFileOpenPath(args.Path).Build())
}

func (fileSec *FileSecurity) OnFinish(op *os.FileOperation, res *os.FileOperationResult) {
	result := &waf.WafOperationResult{}
	op.FinishInspect(result)

	if result.IsBlock() {
		res.BlockErr = result.BlockErr
	}
}
