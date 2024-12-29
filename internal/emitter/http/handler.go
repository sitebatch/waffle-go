package http

import (
	"net/http"
)

type Options struct {
	OnBlockFunc func()
}

func BlockHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
}

func handle(w http.ResponseWriter, r *http.Request, options Options) (http.ResponseWriter, *http.Request, bool, func()) {
	op, ctx := StartHTTPRequestHandlerOperation(r.Context(), buildHttpRequestHandlerOperationArg(r))
	tr := r.WithContext(ctx)

	blocked := false
	afterHandler := func() {
		result := &HTTPRequestHandlerOperationResult{}
		op.Finish(result)

		if result.BlockErr != nil {
			blocked = true
			BlockHandler().ServeHTTP(w, tr)
			if options.OnBlockFunc != nil {
				options.OnBlockFunc()
			}
		}
	}

	if op.IsBlock() {
		blocked = true
		BlockHandler().ServeHTTP(w, tr)
	}

	return w, tr, blocked, afterHandler
}

func WrapHandler(handler http.Handler, options Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw, tr, blocked, afterHandler := handle(w, r, options)
		defer afterHandler()

		if blocked {
			return
		}

		handler.ServeHTTP(tw, tr)
	})
}
