package gin_test

import (
	_ "github.com/mattn/go-sqlite3"

	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sitebatch/waffle-go"
	ginWaf "github.com/sitebatch/waffle-go/contrib/gin-gonic/gin"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type requestParams struct {
	File string `form:"file" json:"file"`
}

type mockEventExporter struct {
	events []waf.DetectionEvent
}

func (m *mockEventExporter) Export(_ context.Context, events waf.ReadOnlyDetectionEvents) error {
	m.events = append(m.events, events.Events()...)

	return nil
}

func TestWafMiddleware(t *testing.T) {
	r := setupRouter()

	testCases := map[string]struct {
		req                  *http.Request
		wantStatusCode       int
		wantResponseBody     string
		wantDetectionRuleIDs []string
	}{
		"Successful read file": {
			req: func() *http.Request {
				form := url.Values{}
				form.Add("file", "README.md")
				body := bytes.NewBufferString(form.Encode())
				r := httptest.NewRequest("POST", "/file", body)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			wantStatusCode:       200,
			wantResponseBody:     `file read successful`,
			wantDetectionRuleIDs: []string{},
		},
		"Failed read file": {
			req: func() *http.Request {
				form := url.Values{}
				form.Add("file", "non_existent_file.md")
				body := bytes.NewBufferString(form.Encode())
				r := httptest.NewRequest("POST", "/file", body)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			wantStatusCode:       500,
			wantResponseBody:     `file read error`,
			wantDetectionRuleIDs: []string{},
		},
		"Block read sensitive file": {
			req: func() *http.Request {
				form := url.Values{}
				form.Add("file", "/var/run/secrets/path/to/file")
				body := bytes.NewBufferString(form.Encode())
				r := httptest.NewRequest("POST", "/file", body)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			wantStatusCode:       403,
			wantResponseBody:     `request blocked`,
			wantDetectionRuleIDs: []string{"sensitive-file-opened"},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			eventExporter := &mockEventExporter{}
			waffle.SetExporter(eventExporter)
			waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))
			require.NoError(t, waffle.Start())

			w := httptest.NewRecorder()

			r.ServeHTTP(w, tt.req)
			assert.Equal(t, tt.wantStatusCode, w.Code)
			assert.Equal(t, tt.wantResponseBody, w.Body.String())

			ruleIDs := make([]string, 0, len(eventExporter.events))
			for _, evt := range eventExporter.events {
				ruleIDs = append(ruleIDs, evt.Rule.ID)
			}

			assert.Equal(t, tt.wantDetectionRuleIDs, ruleIDs)
		})
	}
}

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(ginWaf.WafMiddleware())
	r.POST("/file", func(c *gin.Context) {
		readFile(c)
	})
	return r
}

func readFile(c *gin.Context) {
	var req requestParams
	if err := c.ShouldBind(&req); err != nil {
		c.Data(http.StatusBadRequest, "text/html", []byte("bad request"))
		return
	}

	if _, err := waffleOs.ProtectReadFile(c.Request.Context(), req.File); err != nil {
		c.Data(http.StatusInternalServerError, "text/html", []byte("file read error"))
		return
	}

	c.Data(http.StatusOK, "text/html", []byte("file read successful"))
}
