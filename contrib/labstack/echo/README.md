# labstack/echo

This package provides a Waffle middleware for [Echo](https://echo.labstack.com/).

If you are using Echo web framework, you can apply WAF protection using the `WafMiddleware` provided by this package.

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/labstack/echo
```

## Usage

```go
package main

import (
	"net/http"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sitebatch/waffle-go"
	waffleEcho "github.com/sitebatch/waffle-go/contrib/labstack/echo"
)

func main() {
	e := echo.New()

	// Apply Waffle WAF middleware
	e.Use(waffleEcho.WafMiddleware())

	// Start Waffle
	if err := waffle.Start(); err != nil {
		e.Logger.Fatal(err)
	}

	e.Logger.Fatal(e.Start(":1323"))
}
```
