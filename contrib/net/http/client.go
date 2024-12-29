package http

import (
	"net/http"

	httpEmitter "github.com/sitebatch/waffle-go/internal/emitter/http"
)

func WrapClient(c *http.Client, opts ...httpEmitter.RoundTripOption) *http.Client {
	return httpEmitter.WrapClient(c, opts...)
}
