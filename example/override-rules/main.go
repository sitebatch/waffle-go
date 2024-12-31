package main

import (
	_ "embed"
	"net/http"

	"github.com/sitebatch/waffle-go"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
)

//go:embed custom-rules.json
var rulesJSON []byte

func main() {
	waffle.Start(waffle.WithDebug(), waffle.WithOverrideRules(rulesJSON))

	srv := &http.Server{
		Addr:    ":8000",
		Handler: newHTTPHandler(),
	}

	srv.ListenAndServe()
}

func ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong"))
}

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/ping", http.HandlerFunc(ping))

	handler := waffleHttp.WafMiddleware(mux)
	return handler
}
