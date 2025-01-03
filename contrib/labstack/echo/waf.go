package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"
	httpHandler "github.com/sitebatch/waffle-go/internal/emitter/http"
)

// WafMiddleware is a middleware for lanstack/echo that protects common web attacks.
func WafMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var err error
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				err = next(c)
			})

			httpHandler := httpHandler.WrapHandler(handler, httpHandler.Options{})
			httpHandler.ServeHTTP(c.Response().Writer, c.Request())

			return err
		}
	}
}
