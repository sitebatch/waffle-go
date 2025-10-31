# waffle-go

Waffle is a library for integrating a Web Application Firewall (WAF) into Go applications.

By embedding the WAF directly within the application rather than at the network boundary, you can achieve more accurate and flexible detection and defense against attacks.

## Features

- Integration with minimal code changes
- Protection against common web attacks including XSS, SQL injection, and SSRF
- Protection against business logic vulnerabilities like Account Takeover
- Support for popular Go web frameworks and libraries

## Use Cases

- Protecting web applications and APIs from common web attacks
- Alternative to traditional network-based WAFs for application-level protection
- Enhanced security for applications using database access and file operations

## Getting Started

First, set up the Waffle library.

```bash
go get github.com/sitebatch/waffle-go
```

```go
package main

import (
    "net/http"
    "github.com/sitebatch/waffle-go"
)

func main() {
    // Start Waffle
    if err := waffle.Start(); err != nil {
        // handle error
    }
}
```

Finally, depending on which libraries your application uses, install the Waffle contrib package and apply the middleware or wrapper function.  
The following libraries are supported:

| Library      | Contrib Package                                                |
| :----------- | :------------------------------------------------------------- |
| Gin          | [contrib/gin-gonic/gin](contrib/gin-gonic/gin/README.md)       |
| Echo         | [contrib/labstack/echo](contrib/labstack/echo/README.md)       |
| net/http     | [contrib/net/http](contrib/net/http/README.md)                 |
| gqlgen       | [contrib/99designs/gqlgen](contrib/99designs/gqlgen/README.md) |
| database/sql | [contrib/database/sql](contrib/database/sql/README.md)         |
| os           | [contrib/os](contrib/os/README.md)                             |

### Example

The following example uses a basic `net/http` application.
Full example code can be found in the [examples/auth](./examples/auth/).

This application only provides authentication functionality via the /login endpoint.
The `login()` function executed during login is vulnerable to SQL injection.

<details><summary>Click to expand code</summary>

```go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var database *sql.DB

func init() {
	if err := setupDB(); err != nil {
		log.Fatalf("failed to setup database: %v", err)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      newHTTPHandler(),
	}

	log.Printf("starting server at %s", srv.Addr)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-srvErr:
		log.Fatal(err)
	case <-ctx.Done():
		stop()
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		log.Fatalf("server shutdown failed: %v", err)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	if err := login(r.Context(), email, password); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "login successful")
}

func login(ctx context.Context, email, password string) error {
    // Vulnerable to SQL injection
	rows, err := database.QueryContext(ctx, fmt.Sprintf(
		"SELECT * FROM users WHERE email = '%s' AND password = '%s';", email, password,
	))
	if err != nil {
		return err
	}

	defer rows.Close()

	if !rows.Next() {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r)
	})

	return mux
}

func setupDB() error {
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE users(id int, email text, password text);"); err != nil {
		return err
	}

	if _, err := db.Exec("INSERT INTO users(id, email, password) VALUES(1, 'user@example.com', 'password');"); err != nil {
		return err
	}

	database = db

	return nil
}
```

</details>

### Initialize Waffle

First, initialize Waffle at the start of your application.

```go
func main() {
    ...
    // SetBlockResponseTemplateHTML sets the response body returned when a request is blocked.
    // Here, we set it to "request blocked".
	waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))
    // SetExporter sets the exporter to retrieve detection events.
    // Here, we use the built-in StdoutExporter to log events to stdout.
	waffle.SetExporter(exporter.NewStdoutExporter())

    // Start Waffle
	if err := waffle.Start(); err != nil {
		log.Fatalf("failed to start waffle: %v", err)
	}
    ...
}
```

### Apply Middleware to HTTP Handlers

Next, wrap your HTTP handlers with Waffle's HTTP middleware.
By adding this middleware, Waffle can monitor HTTP requests to detect and block suspicious payloads.

```go
import (
    ...
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
    ...
)

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r)
	})

    // Wrap the mux with Waffle's HTTP middleware
	handler := waffleHttp.WafMiddleware(mux)
	return handler
}
```

At this point, Waffle can inspect HTTP requests to detect SQL injection attempts.

```shell
$ curl -X POST 'http://localhost:8080/login' --data "email=user@example.com' OR 1=1--&password=password"
login successful

# Waffle's exporter log output:
2025/10/31 15:46:45 logger.go:41: "msg"="" "error"="detected sqli payload: SQLi detected" "detected_at"="2025-10-31 15:46:45.809583 +0900 JST m=+13.611103459" "request_url"="http://localhost:8080/login" "rule_id"="sql-injection-attempts" "block"=false "meta"={}
```

However, this only detects payloads that "look like" SQL injections.
This leads to false positives, where a detection occurs even if there is no actual SQL injection vulnerability in the code.

### Apply SQL Wrapper to Database Access

Waffle provides a SQL wrapper that can monitor SQL queries executed via the `database/sql` package.
By wrapping database connections with this wrapper, Waffle can accurately detect and block actual SQL injection attempts.

```go
import (
    ...
    waffleSQL "github.com/sitebatch/waffle-go/contrib/database/sql"
    ...
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	if err := login(r.Context(), email, password); err != nil {
        // Check if the error is a security blocking error
		if waf.IsSecurityBlockingError(err) {
			return
		}

		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "login successful")
}

func setupDB() error {
    // Wrap the database connection with Waffle's SQL wrapper
	db, err := waffleSQL.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		return err
	}

    ...

	database = db

	return nil
}
```

When a request is sent that triggers SQL injection, Waffle inspects the SQL that will be executed (not the HTTP request) and blocks it.

```shell
$ curl -X POST 'http://localhost:8080/login' --data "email=user@example.com' OR 1=1--&password=password"
request blocked

# Waffle's exporter log output:
2025/10/31 16:15:19 logger.go:41: "msg"="" "error"="detected sql injection, because of where tautology" "detected_at"="2025-10-31 16:15:19.901821 +0900 JST m=+1081.473456834" "request_url"="http://localhost:8080/login" "rule_id"="sql-injection-exploited" "block"=true "meta"={}
```

### Next Steps

Waffle also provides protection against other attack vectors, such as directory traversal, SSRF, and more.
For more details, please refer to the README of each [contrib package](./contrib/).

## Configuration

### Custom Rules

You can provide custom WAF rules:

```go
waffle.Start(waffle.WithRule(customRuleJSON))
```

### Error Handling

Set a custom handler to handle Waffle's internal errors.

```go
waffle.SetErrorHandler(customErrorHandler)
```

### Event Export

To retrieve events detected by Waffle, configure an exporter using `SetExporter()`.

Waffle provides built-in exporters like `StdoutExporter` for logging detection events and `ChanExporter` for writing to a specified channel, but you can also implement and configure your own custom exporter that meets the required interface.

```go
waffle.SetExporter(customExporter)
```

### Logging

Set a custom logger to capture Waffle's internal logs.

```go
waffle.SetLogger(logger)
```

## Handling blocking event

When Waffle detects an attack and blocks the request, it returns a `waf.SecurityBlockingError` error type. If you catch this error, you should handle it appropriately—for example, by returning a proper error response to the client.
This error type can be checked using the `waf.IsSecurityBlockingError` function.

When Waffle's HTTP middleware blocks a request, it automatically returns an HTTP 403 Forbidden response, but it is your responsibility to handle the blocked function call.
For instance, if a function called during processing at an endpoint attempts to execute a potentially vulnerable SQL query (such as SQL Injection), that function call will be blocked and terminated by returning an error of type `waf.SecurityBlockingError`.
You can determine whether the block was initiated by the WAF using either `errors.As` or `waf.IsSecurityBlockingError`.

```go
// Example of handling a blocked SQL query

// Will be blocked due to SQL Injection attempt
userInput := "1 OR 1 = 1"
_, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userInput))
if err != nil {
    if waf.IsSecurityBlockingError(err) {
        // Handle blocked request
        log.Printf("Blocked request: %v", err)
        return
    }

    // Handle other errors
    log.Fatal(err)
}
```
