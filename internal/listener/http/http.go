package http

import (
	httpEmitter "github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type HTTPSecurity struct{}

func (h *HTTPSecurity) Name() string {
	return "http_security"
}

func NewHTTPSecurity(rootOp operation.Operation) (listener.Listener, error) {
	httpSec := &HTTPSecurity{}

	operation.OnStart(rootOp, httpSec.OnRequest)
	operation.OnFinish(rootOp, httpSec.OnFinish)
	return httpSec, nil
}

func (httpSec *HTTPSecurity) OnRequest(op *httpEmitter.HTTPRequestHandlerOperation, args httpEmitter.HTTPRequestHandlerOperationArg) {
	op.Run(
		op,
		*inspector.
			NewInspectDataBuilder(op.OperationContext()).
			WithHTTPRequestURL(args.URL).
			WithHTTPRequestHeader(args.Headers).
			WithHTTPRequestQuery(args.QueryValues).
			WithHTTPRequestBody(args.Body).
			WithClientIP(args.ClientIP).
			Build(),
	)
}

func (httpSec *HTTPSecurity) OnFinish(op *httpEmitter.HTTPRequestHandlerOperation, res *httpEmitter.HTTPRequestHandlerOperationResult) {
	result := &waf.WafOperationResult{}
	op.FinishInspect(result)

	if result.IsBlock() {
		res.BlockErr = result.BlockErr
	}
}
