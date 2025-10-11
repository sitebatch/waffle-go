package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sitebatch/waffle-go/internal/emitter/http/parser"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type HTTPRequestHandlerOperation struct {
	operation.Operation
	*waf.WafOperation
}

type HTTPRequestHandlerOperationArg struct {
	URL         string
	Path        string
	Headers     map[string][]string
	QueryValues map[string][]string
	Body        map[string][]string
	ClientIP    string
}

type HTTPRequestHandlerOperationResult struct {
	BlockErr error
}

func (HTTPRequestHandlerOperationArg) IsArgOf(*HTTPRequestHandlerOperation)        {}
func (*HTTPRequestHandlerOperationResult) IsResultOf(*HTTPRequestHandlerOperation) {}

func StartHTTPRequestHandlerOperation(ctx context.Context, args HTTPRequestHandlerOperationArg) (*HTTPRequestHandlerOperation, context.Context) {
	wafOp, found := operation.FindOperation[waf.WafOperation](ctx)
	if !found {
		wafOp, ctx = waf.StartWafOperation(ctx, waf.WithHttpRequstContext(wafcontext.HttpRequest{
			URL:      args.URL,
			Headers:  args.Headers,
			Body:     args.Body,
			ClientIP: args.ClientIP,
		}))
	}

	op := &HTTPRequestHandlerOperation{
		Operation:    operation.NewOperation(wafOp),
		WafOperation: wafOp,
	}

	return op, operation.StartAndSetOperation(ctx, op, args)
}

func (op *HTTPRequestHandlerOperation) Finish(res *HTTPRequestHandlerOperationResult) {
	operation.FinishOperation(op, res)
}

func buildHttpRequestHandlerOperationArg(r *http.Request) HTTPRequestHandlerOperationArg {
	body, err := parser.ParseHTTPRequestBody(r)
	if err != nil {
		log.Error("failed to parse http request body", "error", err)
		body = map[string][]string{}
	}
	return HTTPRequestHandlerOperationArg{
		URL:         BuildFullURL(r),
		Path:        r.URL.Path,
		Headers:     r.Header,
		QueryValues: r.URL.Query(),
		Body:        body,
		ClientIP:    r.RemoteAddr,
	}
}

func BuildFullURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if r.URL.RawQuery == "" {
		return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	}

	return fmt.Sprintf("%s://%s%s?%s", scheme, r.Host, r.URL.Path, r.URL.RawQuery)
}
