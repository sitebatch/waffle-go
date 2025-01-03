# labstack/echo

This package provides a Waffle middleware for [Echo](https://echo.labstack.com/).

If you are using Echo, you can apply protection by Waffle using the `WafMiddleware` provided by this package.

## Usage

```go
package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sitebatch/waffle-go"
	waffleEcho "github.com/sitebatch/waffle-go/contrib/labstack/echo"
)

e := echo.New()
e.Use(waffleEcho.WafMiddleware())
e.Use(middleware.Recover())

waffle.Start()

e.Logger.Fatal(e.Start(":1323"))
```
