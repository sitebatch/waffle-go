# gin-gonic/gin

This package provides a Waffle middleware for [gin](https://gin-gonic.com/).

If you are using Gin web framework, you can apply WAF protection using the `WafMiddleware` provided by this package.

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/gin-gonic/gin
```

## Usage

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/sitebatch/waffle-go"
	ginWaf "github.com/sitebatch/waffle-go/contrib/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Apply Waffle WAF middleware
	r.Use(ginWaf.WafMiddleware())

	// Start Waffle
	if err := waffle.Start(); err != nil {
		panic(err)
	}

	r.Run(":8000")
}
```
