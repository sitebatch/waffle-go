# labstack/echo

This package provides a Waffle middleware for [Echo](https://echo.labstack.com/).

If you are using Echo, you can apply protection by Waffle using the `WafMiddleware` provided by this package.

## Usage

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sitebatch/waffle-go"
	waffleEcho "github.com/sitebatch/waffle-go/contrib/labstack/echo"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
)

func main() {
	// A vulnerable function that reads any file.
	readFileFunc := func(c echo.Context) error {
		path := c.QueryParam("path")
		// Protect sensitive files from access, etc. using the ProtectReadFile function of Waffle.
		if _, err := waffleOs.ProtectReadFile(c.Request().Context(), path); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.String(http.StatusOK, "file read")
	}

	e := echo.New()
	e.Use(waffleEcho.WafMiddleware())
	e.Use(middleware.Recover())

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.GET("/read-file", func(c echo.Context) error {
		return readFileFunc(c)
	})

	waffle.Start()

	e.Logger.Fatal(e.Start(":1323"))
}
```
