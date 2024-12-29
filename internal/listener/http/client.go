package http

import (
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type HTTPClientSecurity struct{}

func (s *HTTPClientSecurity) Name() string {
	return "http_client_security"
}

func NewHTTPClientSecurity(rootOp operation.Operation) (listener.Listener, error) {
	httpClientSec := &HTTPClientSecurity{}

	operation.OnStart(rootOp, httpClientSec.OnRequest)
	operation.OnFinish(rootOp, httpClientSec.OnFinish)
	return httpClientSec, nil
}

func (httpClientSec *HTTPClientSecurity) OnRequest(op *http.HTTPClientRequestOperation, args http.HTTPClientRequestOperationArg) {
	op.Run(op, *inspector.NewInspectDataBuilder().WithHTTPClientRequestURL(args.URL).Build())
}

func (httpClientSec *HTTPClientSecurity) OnFinish(op *http.HTTPClientRequestOperation, res *http.HTTPClientRequestOperationResult) {
	result := &waf.WafOperationResult{}
	op.FinishInspect(result)

	if result.IsBlock() {
		res.BlockErr = result.BlockErr
	}
}
