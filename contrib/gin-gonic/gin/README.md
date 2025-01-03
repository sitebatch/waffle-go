# gin-gonic/gin

This package provides a Waffle middleware for [gin](https://gin-gonic.com/).

If you are using gin, you can apply protection by Waffle using the `WafMiddleware` provided by this package.

## Usage

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/sitebatch/waffle-go"
	ginWaf "github.com/sitebatch/waffle-go/contrib/gin-gonic/gin"
)

r := gin.Default()
r.Use(ginWaf.WafMiddleware())

waffle.Start()

r.Run(":8000")
```
