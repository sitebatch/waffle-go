package echo_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sitebatch/waffle-go"
	waffleEcho "github.com/sitebatch/waffle-go/contrib/labstack/echo"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
	"github.com/sitebatch/waffle-go/internal/rule/testdata"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEventExporter struct {
	events []waf.DetectionEvent
}

func (m *mockEventExporter) Export(_ context.Context, events waf.ReadOnlyDetectionEvents) error {
	m.events = append(m.events, events.Events()...)

	return nil
}

func TestWafMiddleware(t *testing.T) {
	testCases := map[string]struct {
		controller           func(c echo.Context) error
		req                  *http.Request
		wantStatusCode       int
		wantResponseBody     string
		wantDetectionRuleIDs []string
	}{
		"not blocked": {
			controller: func(c echo.Context) error {
				return c.String(http.StatusOK, "Hello")
			},
			req:                  mustNewRequest(t, http.MethodGet, "/", nil),
			wantStatusCode:       200,
			wantResponseBody:     "Hello",
			wantDetectionRuleIDs: []string{},
		},
		"detect request": {
			controller: func(c echo.Context) error {
				return c.String(http.StatusOK, "pong")
			},
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("User-Agent", "detect-security-scanner")
				return r
			}(),
			wantStatusCode:       200,
			wantResponseBody:     "pong",
			wantDetectionRuleIDs: []string{"detect-security-scanner"},
		},
		"block request": {
			controller: func(c echo.Context) error {
				if _, err := waffleOs.ProtectReadFile(c.Request().Context(), "/var/run/secrets/path/to/file"); err != nil {
					if waf.IsSecurityBlockingError(err) {
						return nil
					}
					return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
				}
				return c.String(http.StatusOK, "file read")
			},
			req:                  mustNewRequest(t, http.MethodGet, "/?file=/var/run/secrets/path/to/file", nil),
			wantStatusCode:       403,
			wantResponseBody:     "request blocked",
			wantDetectionRuleIDs: []string{"sensitive-file-opened"},
		},
		"block by http middleware": {
			controller: func(c echo.Context) error {
				return c.String(http.StatusOK, "Hello")
			},
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("User-Agent", "block-security-scanner")
				return r
			}(),
			wantStatusCode:       403,
			wantResponseBody:     "request blocked",
			wantDetectionRuleIDs: []string{"block-security-scanner"},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			e := echo.New()
			e.Use(waffleEcho.WafMiddleware())
			e.Any("/*", tt.controller)

			eventExporter := &mockEventExporter{}
			waffle.SetExporter(eventExporter)
			waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))
			require.NoError(t, waffle.Start(
				waffle.WithRule(testdata.MustReadRule(t, "../../../internal/rule/testdata/rules.json")),
			))

			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, tt.req)

			assert.Equal(t, tt.wantStatusCode, rec.Code)
			assert.Equal(t, tt.wantResponseBody, rec.Body.String())

			ruleIDs := make([]string, 0, len(eventExporter.events))
			for _, evt := range eventExporter.events {
				ruleIDs = append(ruleIDs, evt.Rule.ID)
			}

			assert.Equal(t, tt.wantDetectionRuleIDs, ruleIDs)
		})
	}
}

func mustNewRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		require.NoError(t, err)
	}

	return req
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

	if err := waffle.Start(); err != nil {
		e.Logger.Fatal(err)
	}

	e.Logger.Fatal(e.Start(":1323"))
}
