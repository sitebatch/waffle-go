package http

import (
	"net/http"

	httpHandler "github.com/sitebatch/waffle-go/internal/emitter/http"
)

// WafMiddleware is a middleware that protects HTTP requests from attacks.
func WafMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpHandler.WrapHandler(next, httpHandler.Options{}).ServeHTTP(w, r)
	})
}
