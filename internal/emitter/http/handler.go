package http

import (
	"net/http"

	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/internal/log"
)

type Options struct {
	OnBlockFunc func()
}

func handle(w http.ResponseWriter, r *http.Request, options Options) (http.ResponseWriter, *http.Request, bool, func()) {
	ww, waffleResponseWriter := action.NewWaffleResponseWriter(w)
	op, ctx := StartHTTPRequestHandlerOperation(r.Context(), buildHttpRequestHandlerOperationArg(r))
	rr := r.WithContext(ctx)

	blocked := false
	afterHandler := func() {
		result := &HTTPRequestHandlerOperationResult{}
		op.Finish(result)

		if result.BlockErr != nil {
			blocked = true
			if waffleResponseWriter.BodyWritten() {
				log.Warn("response body is already written, will not respond with block page")
			} else {
				action.BlockResponseHandler().ServeHTTP(ww, rr)
				if options.OnBlockFunc != nil {
					options.OnBlockFunc()
				}
			}
		}
	}

	if op.IsBlock() {
		blocked = true
		if waffleResponseWriter.BodyWritten() {
			log.Warn("response body is already written, will not respond with block page")
		} else {
			action.BlockResponseHandler().ServeHTTP(ww, rr)
		}
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
