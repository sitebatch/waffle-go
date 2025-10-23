package http

import (
	"net/http"

	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/handler/response"
)

type Options struct {
	OnBlockFunc func()
}

func handle(w http.ResponseWriter, r *http.Request, options Options) (http.ResponseWriter, *http.Request, bool, func()) {
	ww, waffleResponseWriter := response.NewWaffleResponseWriter(w)
	op, ctx := StartHTTPRequestHandlerOperation(r.Context(), BuildHttpRequestHandlerOperationArg(r))
	rr := r.WithContext(ctx)

	blocked := false
	afterHandler := func() {
		result := &HTTPRequestHandlerOperationResult{}
		op.Finish(result)

		if result.BlockErr != nil {
			waffleResponseWriter.Reset()
			blocked = true

			response.BlockResponseHandler().ServeHTTP(waffleResponseWriter, rr)
			if options.OnBlockFunc != nil {
				options.OnBlockFunc()
			}
		}

		if err := waffleResponseWriter.Commit(); err != nil {
			handler.GetErrorHandler().HandleError(err)
		}
	}

	if op.IsBlock() {
		blocked = true

		waffleResponseWriter.Reset()
		response.BlockResponseHandler().ServeHTTP(ww, rr)
	}

	return ww, rr, blocked, afterHandler
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
