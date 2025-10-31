# net/http

This package provides Waffle middleware and HTTP client wrapper for the Go standard library's [net/http](https://pkg.go.dev/net/http).

- **HTTP Server Protection**: `WafMiddleware` that automatically analyzes incoming requests for malicious patterns
- **HTTP Client Protection**: `WrapClient` that prevents outbound requests to dangerous destinations (SSRF protection)

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/net/http
```

## Usage

### HTTP Server Protection

```go
package main

import (
	"net/http"
	"github.com/sitebatch/waffle-go"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
)

func main() {
	mux := http.NewServeMux()

	// Apply Waffle WAF middleware
	handler := waffleHttp.WafMiddleware(mux)

	// Start Waffle
	if err := waffle.Start(); err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr:    ":8000",
		Handler: handler,
	}

	srv.ListenAndServe()
}
```

### HTTP Client Protection (SSRF Prevention)

```go
package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sitebatch/waffle-go"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	"github.com/sitebatch/waffle-go/waf"
)

func main() {
	// Start Waffle
	if err := waffle.Start(); err != nil {
		panic(err)
	}

	// Wrap HTTP client for SSRF protection
	client := waffleHttp.WrapClient(http.DefaultClient)

	// Protected request - Waffle will prevents SSRF attempts
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/", nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		if waf.IsSecurityBlockingError(err) {
			fmt.Printf("Request blocked by Waffle: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
}
```
