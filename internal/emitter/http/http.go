package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/sitebatch/waffle-go/internal/emitter/http/parser"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/waf/wafcontext"
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
	RawBody     []byte
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
		wafOp, ctx = waf.InitializeWafOperation(ctx, waf.WithHttpRequstContext(wafcontext.HttpRequest{
			URL:      args.URL,
			Headers:  args.Headers,
			RawBody:  args.RawBody,
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

func BuildHttpRequestHandlerOperationArg(r *http.Request) HTTPRequestHandlerOperationArg {
	rawBody := readBody(r)
	body, err := parser.ParseHTTPRequestBody(r)
	if err != nil || body == nil {
		body = map[string][]string{}
	}
	return HTTPRequestHandlerOperationArg{
		URL:         BuildFullURL(r),
		Path:        r.URL.Path,
		Headers:     r.Header,
		QueryValues: r.URL.Query(),
		RawBody:     rawBody,
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

func readBody(r *http.Request) []byte {
	ctx := r.Context()
	copy := r.Clone(ctx)
	if copy.Body == nil {
		return nil
	}

	b, err := io.ReadAll(copy.Body)
	if err != nil {
		return nil
	}
	defer copy.Body.Close()

	r.Body = io.NopCloser(bytes.NewBuffer(b))

	return b
}
