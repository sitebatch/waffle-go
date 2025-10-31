# gqlgen

This package provides a Waffle middleware for [gqlgen](https://gqlgen.com/).

If you are using gqlgen for GraphQL server, you can apply WAF protection using the `WafMiddleware` provided by this package.

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/99designs/gqlgen
```

## Usage

```go
package main

import (
	"net/http"
	"github.com/99designs/gqlgen/graphql/handler"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/contrib/99designs/gqlgen"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
)

func main() {
	mux := http.NewServeMux()

	gqlHandler := func() http.HandlerFunc {
		srv := handler.New(graph.NewExecutableSchema(graph.Config{
			Resolvers: &graph.Resolver{},
		}))

		// Apply Waffle WAF middleware for GraphQL
		srv.Use(gqlgen.WafMiddleware{})

		return func(w http.ResponseWriter, r *http.Request) {
			srv.ServeHTTP(w, r)
		}
	}

	mux.Handle("/query", gqlHandler())

	// Apply WAF middleware for the HTTP server
	handler := waffleHttp.WafMiddleware(mux)

	// Start Waffle
	if err := waffle.Start(); err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	srv.ListenAndServe()
}
```
