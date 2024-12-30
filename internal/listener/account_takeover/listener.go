package account_takeover

import (
	"github.com/sitebatch/waffle-go/internal/emitter/account_takeover"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type AccountTakeoverSecurity struct {
}

func (s *AccountTakeoverSecurity) Name() string {
	return "account_takeover_security"
}

func NewAccountTakeoverSecurity(rootOp operation.Operation) (listener.Listener, error) {
	accountTakeoverSec := &AccountTakeoverSecurity{}

	operation.OnStart(rootOp, accountTakeoverSec.OnLogin)
	operation.OnFinish(rootOp, accountTakeoverSec.OnFinish)

	return accountTakeoverSec, nil
}

func (s *AccountTakeoverSecurity) OnLogin(op *account_takeover.ProtectLoginOperation, args account_takeover.ProtectLoginOperationArg) {
	op.Run(op, *inspector.NewInspectDataBuilder().WithAccountTakeover(args.ClientIP, args.UserID).Build())
}

func (s *AccountTakeoverSecurity) OnFinish(op *account_takeover.ProtectLoginOperation, res *account_takeover.ProtectLoginOperationResult) {
	result := &waf.WafOperationResult{}
	op.FinishInspect(result)

	if result.IsBlock() {
		res.BlockErr = result.BlockErr
	}
}
