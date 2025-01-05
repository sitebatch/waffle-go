# gqlgen

This package provides a Waffle middleware for [gqlgen](https://gqlgen.com/).

If you are using gqlgen, you can apply protection by Waffle using the `WafMiddleware` provided by this package.

## Usage

```go
import (
	"github.com/sitebatch/waffle-go/contrib/99designs/gqlgen"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
)

mux := http.NewServeMux()

gqlHandler := func() http.HandlerFunc {
	srv := handler.New(graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{}}))
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})

	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))

    // Apply WAF middleware for gqlgen
	srv.Use(gqlgen.WafMiddleware{})

	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New[string](100),
	})

	return func(w http.ResponseWriter, r *http.Request) {
		srv.ServeHTTP(w, r)
	}
}

mux.Handle("/query", gqlHandler())
// Apply WAF middleware for the HTTP Server
handler := waffleHttp.WafMiddleware(mux)
```
