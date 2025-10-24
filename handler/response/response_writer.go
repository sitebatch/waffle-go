package response

import (
	"bytes"
	"net/http"
)

type WaffleResponseWriter struct {
	http.ResponseWriter

	// status is the HTTP status code written to the ResponseWriter.
	status int

	buf *bytes.Buffer
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
	if w.status != 0 {
		return
	}

	w.status = status
}

func (w *WaffleResponseWriter) Write(b []byte) (int, error) {
	return w.buf.Write(b)
}

func (w *WaffleResponseWriter) Status() int {
	return w.status
}

func (w *WaffleResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *WaffleResponseWriter) Reset() {
	w.buf.Reset()
	w.status = 0
}

func (w *WaffleResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *WaffleResponseWriter) Commit() error {
	if w.status == 0 {
		w.ResponseWriter.WriteHeader(http.StatusOK)
	} else {
		w.ResponseWriter.WriteHeader(w.status)
	}

	if _, err := w.ResponseWriter.Write(w.buf.Bytes()); err != nil {
		return err
	}

	w.buf.Reset()

	return nil
}
