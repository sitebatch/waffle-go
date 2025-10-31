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
