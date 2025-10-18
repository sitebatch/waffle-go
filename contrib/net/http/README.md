# net/http

This package provides a Waffle middleware and HTTP Client for the Go standard library's [net/http](https://pkg.go.dev/net/http).

If your application uses `net/http`, you can apply Waffle protection using this package.  
Additionally, if you are using an HTTP client with `net/http`, you can protect against threats such as SSRF by using the wrapper functions provided by this package.

## Usage

```go
import (
   	"github.com/sitebatch/waffle-go"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
)

func main() {
   	mux := http.NewServeMux()
	handler := waffleHttp.WafMiddleware(mux)

	waffle.Start()

	srv := &http.Server{
		Addr:    ":8000",
		Handler: handler,
	}

	srv.ListenAndServe()
}
```

### HTTP Client

```go
import (
    "net/http"

   	"github.com/sitebatch/waffle-go"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
}

c := waffleHttp.WrapClient(http.DefaultClient)
req, _ := stdhttp.NewRequestWithContext(ctx, "GET", url, nil)
```
