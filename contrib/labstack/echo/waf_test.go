package echo_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sitebatch/waffle-go"
	waffleEcho "github.com/sitebatch/waffle-go/contrib/labstack/echo"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
	"github.com/stretchr/testify/assert"
)

func TestWafMiddleware(t *testing.T) {
	testCases := map[string]struct {
		controller func(c echo.Context) error
		req        *http.Request
		expectErr  bool
	}{
		"not blocked": {
			controller: func(c echo.Context) error {
				return c.String(http.StatusOK, "Hello")
			},
			req:       httptest.NewRequest(http.MethodGet, "/", nil),
			expectErr: false,
		},
		"blocked": {
			controller: func(c echo.Context) error {
				path := c.QueryParam("path")
				if _, err := waffleOs.ProtectReadFile(c.Request().Context(), path); err != nil {
					return echo.NewHTTPError(http.StatusForbidden, err.Error())
				}
				return c.String(http.StatusOK, "file read")
			},
			req:       httptest.NewRequest(http.MethodGet, "/?path=/var/run/secrets/path/to/file", nil),
			expectErr: true,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(tt.req, rec)

			waf := waffleEcho.WafMiddleware()
			h := waf(tt.controller)

			waffle.Start()

			actual := h(c)

			if tt.expectErr {
				assert.Error(t, actual)
				assert.Contains(t, actual.Error(), "blocked by rule sensitive-file-opened")
				return
			}

			assert.NoError(t, actual)
		})
	}
}

func ExampleWafMiddleware() {
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
