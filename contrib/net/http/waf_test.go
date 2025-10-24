package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/action"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
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
		controller           http.Handler
		req                  *http.Request
		wantStatusCode       int
		wantResponseBody     string
		wantDetectionRuleIDs []string
	}{
		"not blocked": {
			controller: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte("Hello"))
				require.NoError(t, err)
			}),
			req:                  mustNewRequest(t, http.MethodGet, "/", nil),
			wantStatusCode:       200,
			wantResponseBody:     "Hello",
			wantDetectionRuleIDs: []string{},
		},
		"blocked": {
			controller: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := waffleOs.ProtectReadFile(r.Context(), "/var/run/secrets/path/to/file"); err != nil {
					if action.IsBlockError(err) {
						// WAF has already handled the block response.
						return
					}

					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_, err := w.Write([]byte("file read"))
				require.NoError(t, err)
			}),
			req:                  mustNewRequest(t, http.MethodGet, "/?file=/var/run/secrets/path/to/file", nil),
			wantStatusCode:       403,
			wantResponseBody:     "request blocked",
			wantDetectionRuleIDs: []string{"sensitive-file-opened"},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/", tt.controller)
			handler := waffleHttp.WafMiddleware(mux)

			eventExporter := &mockEventExporter{}
			waffle.SetExporter(eventExporter)
			waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))
			require.NoError(t, waffle.Start())

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tt.req)

			assert.Equal(t, tt.wantStatusCode, rr.Code)
			assert.Equal(t, tt.wantResponseBody, rr.Body.String())

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
