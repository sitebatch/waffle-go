package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	httpHandler "github.com/sitebatch/waffle-go/internal/emitter/http"
)

func wafHandler(c *gin.Context) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Request = r
		c.Next()
	})

	options := httpHandler.Options{
		OnBlockFunc: func() {
			c.Abort()
		},
	}

	httpHandler.WrapHandler(handler, options).ServeHTTP(c.Writer, c.Request)
}

// WafMiddleware is a middleware that protects HTTP requests from attacks.
func WafMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		wafHandler(c)
		c.Next()
	}
}
