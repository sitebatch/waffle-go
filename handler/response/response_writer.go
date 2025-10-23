package response

import (
	"net/http"
)

type WaffleResponseWriter struct {
	http.ResponseWriter

	// status is the HTTP status code written to the ResponseWriter.
	status int
	// headerWritten is true if the response header has been written.
	headerWritten bool
	// bodyWritten is true if the response body has been written.
	bodyWritten bool
}

var (
	_ http.ResponseWriter = (*WaffleResponseWriter)(nil)
)

// NewWaffleResponseWriter returns a new WaffleResponseWriter.
// The http.ResponseWriter should be the original value passed to the handler, or have an Unwrap method returning the original http.ResponseWriter.
func NewWaffleResponseWriter(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
	feature := 0
	if _, ok := w.(http.CloseNotifier); ok {
		feature |= closeNotifier
	}
	if _, ok := w.(http.Flusher); ok {
		feature |= flusher
	}
	if _, ok := w.(http.Hijacker); ok {
		feature |= hijacker
	}
	if _, ok := w.(http.Pusher); ok {
		feature |= pusher
	}

	return featurePicker[feature](w)

}

func (w *WaffleResponseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}

	w.status = status
	w.ResponseWriter.WriteHeader(status)
	w.headerWritten = true
}

func (w *WaffleResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	w.bodyWritten = true
	return w.ResponseWriter.Write(b)
}

func (w *WaffleResponseWriter) Status() int {
	return w.status
}

func (w *WaffleResponseWriter) HeaderWritten() bool {
	return w.headerWritten
}

func (w *WaffleResponseWriter) BodyWritten() bool {
	return w.bodyWritten
}

func (w *WaffleResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
