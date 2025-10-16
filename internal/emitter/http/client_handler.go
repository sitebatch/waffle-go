package http

import (
	"context"
	"net/http"

	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type HTTPClientRequestOperation struct {
	operation.Operation

	*waf.WafOperation
}

type HTTPClientRequestOperationArg struct {
	URL string
}

type HTTPClientRequestOperationResult struct {
	BlockErr error
}

func (HTTPClientRequestOperationArg) IsArgOf(*HTTPClientRequestOperation)        {}
func (*HTTPClientRequestOperationResult) IsResultOf(*HTTPClientRequestOperation) {}

func (res *HTTPClientRequestOperationResult) IsBlock() bool {
	return res.BlockErr != nil
}

type Transport struct {
	rt http.RoundTripper

	cfg *roundTripOption
}

type roundTripOption struct{}

type RoundTripOption func(*roundTripOption)

var _ http.RoundTripper = &Transport{}

func ProtectRoundTrip(ctx context.Context, url string) error {
	parent, _ := operation.FindOperationFromContext(ctx)
	if parent == nil {
		return nil
	}

	var wafop *waf.WafOperation
	if parentOp, ok := parent.(*HTTPClientRequestOperation); ok {
		wafop = parentOp.WafOperation
	} else {
		wafop, _ = waf.InitializeWafOperation(ctx)
	}

	op := &HTTPClientRequestOperation{
		Operation:    operation.NewOperation(wafop),
		WafOperation: wafop,
	}

	operation.StartOperation(
		op, HTTPClientRequestOperationArg{URL: url},
	)

	res := &HTTPClientRequestOperationResult{}
	operation.FinishOperation(op, res)

	if res.IsBlock() {
		return res.BlockErr
	}

	return nil
}

func WrapClient(c *http.Client, opts ...RoundTripOption) *http.Client {
	c.Transport = NewTransport(c.Transport, opts...)
	return c
}

func NewTransport(base http.RoundTripper, opts ...RoundTripOption) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}

	cfg := &roundTripOption{}
	for _, opt := range opts {
		opt(cfg)
	}

	t := Transport{
		rt:  base,
		cfg: cfg,
	}

	return &t
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	r2 := r.Clone(ctx)

	if err := ProtectRoundTrip(ctx, r2.URL.String()); err != nil {
		return nil, err
	}

	return t.rt.RoundTrip(r)
}
