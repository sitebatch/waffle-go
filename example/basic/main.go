package main

import (
	"errors"
	"net/http"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/action"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
)

func main() {
	waffle.Start(waffle.WithDebug())

	srv := &http.Server{
		Addr:    ":8000",
		Handler: newHTTPHandler(),
	}

	srv.ListenAndServe()
}

func ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong"))
}

func readFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("file")

	if _, err := waffleOs.ProtectReadFile(r.Context(), path); err != nil {
		var actionErr *action.BlockError
		if errors.As(err, &actionErr) {
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("file read"))
}

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/ping", http.HandlerFunc(ping))
	mux.Handle("/get-file", http.HandlerFunc(readFile))

	handler := waffleHttp.WafMiddleware(mux)
	return handler
}
