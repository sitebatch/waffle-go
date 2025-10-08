package sql

import (
	"github.com/sitebatch/waffle-go/internal/emitter/sql"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type SQLSecurity struct{}

func (s *SQLSecurity) Name() string {
	return "sql_security"
}

func NewSQLSecurity(rootOp operation.Operation) (listener.Listener, error) {
	sqlSec := &SQLSecurity{}

	operation.OnStart(rootOp, sqlSec.OnQueryOrExec)
	operation.OnFinish(rootOp, sqlSec.OnFinish)
	return sqlSec, nil
}

func (sqlSec *SQLSecurity) OnQueryOrExec(op *sql.SQLOperation, args sql.SQLOperationArg) {
	op.Run(op, *inspector.NewInspectDataBuilder(op.OperationContext()).WithSQLQuery(args.Query).Build())
}

func (sqlSec *SQLSecurity) OnFinish(op *sql.SQLOperation, res *sql.SQLOperationResult) {
	result := &waf.WafOperationResult{}
	op.FinishInspect(result)

	if result.IsBlock() {
		res.BlockErr = result.BlockErr
	}
}
