package response

import (
	"bufio"
	"net"
	"net/http"
)

const (
	closeNotifier = 1 << iota
	flusher
	hijacker
	pusher
)

type (
	closeNotifierFeature struct{ *WaffleResponseWriter }
	flusherFeature       struct{ *WaffleResponseWriter }
	hijackerFeature      struct{ *WaffleResponseWriter }
	pusherFeature        struct{ *WaffleResponseWriter }
)

var featurePicker = make([]func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter), 16)

func (f *closeNotifierFeature) CloseNotify() <-chan bool {
	return f.ResponseWriter.(http.CloseNotifier).CloseNotify()
}

func (f *flusherFeature) Flush() {
	f.ResponseWriter.(http.Flusher).Flush()
}

func (f *hijackerFeature) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.ResponseWriter.(http.Hijacker).Hijack()
}

func (f *pusherFeature) Push(target string, opts *http.PushOptions) error {
	return f.ResponseWriter.(http.Pusher).Push(target, opts)
}

func InitResponseWriterFeature() {
	featurePicker[0] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return ww, ww
	}
	featurePicker[closeNotifier] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
		}{
			ww, &closeNotifierFeature{ww},
		}, ww
	}
	featurePicker[flusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Flusher
		}{
			ww, &flusherFeature{ww},
		}, ww
	}
	featurePicker[hijacker] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Hijacker
		}{
			ww, &hijackerFeature{ww},
		}, ww
	}
	featurePicker[pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Pusher
		}{
			ww, &pusherFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|flusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Flusher
		}{
			ww, &closeNotifierFeature{ww}, &flusherFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|hijacker] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Hijacker
		}{
			ww, &closeNotifierFeature{ww}, &hijackerFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Pusher
		}{
			ww, &closeNotifierFeature{ww}, &pusherFeature{ww},
		}, ww
	}
	featurePicker[flusher|hijacker] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Flusher
			http.Hijacker
		}{
			ww, &flusherFeature{ww}, &hijackerFeature{ww},
		}, ww
	}
	featurePicker[flusher|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Flusher
			http.Pusher
		}{
			ww, &flusherFeature{ww}, &pusherFeature{ww},
		}, ww
	}
	featurePicker[hijacker|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Hijacker
			http.Pusher
		}{
			ww, &hijackerFeature{ww}, &pusherFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|flusher|hijacker] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Flusher
			http.Hijacker
		}{
			ww, &closeNotifierFeature{ww}, &flusherFeature{ww}, &hijackerFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|flusher|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Flusher
			http.Pusher
		}{
			ww, &closeNotifierFeature{ww}, &flusherFeature{ww}, &pusherFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|hijacker|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Hijacker
			http.Pusher
		}{
			ww, &closeNotifierFeature{ww}, &hijackerFeature{ww}, &pusherFeature{ww},
		}, ww
	}
	featurePicker[flusher|hijacker|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.Flusher
			http.Hijacker
			http.Pusher
		}{
			ww, &flusherFeature{ww}, &hijackerFeature{ww}, &pusherFeature{ww},
		}, ww
	}
	featurePicker[closeNotifier|flusher|hijacker|pusher] = func(w http.ResponseWriter) (http.ResponseWriter, *WaffleResponseWriter) {
		ww := &WaffleResponseWriter{ResponseWriter: w}
		return struct {
			*WaffleResponseWriter
			http.CloseNotifier
			http.Flusher
			http.Hijacker
			http.Pusher
		}{
			ww, &closeNotifierFeature{ww}, &flusherFeature{ww}, &hijackerFeature{ww}, &pusherFeature{ww},
		}, ww
	}
}
