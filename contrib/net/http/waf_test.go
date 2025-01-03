package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
	"github.com/sitebatch/waffle-go/internal/action"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWafMiddleware(t *testing.T) {
	testCases := map[string]struct {
		controller http.Handler
		req        *http.Request
		expectErr  bool
	}{
		"not block": {
			controller: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello"))
			}),
			req:       mustNewRequest(t, http.MethodGet, "/", nil),
			expectErr: false,
		},
		"block": {
			controller: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := waffleOs.ProtectReadFile(r.Context(), "/var/run/secrets/path/to/file"); err != nil {
					if _, ok := err.(*action.BlockError); ok {
						http.Error(w, err.Error(), http.StatusForbidden)
						return
					}
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Write([]byte("file read"))
			}),
			req:       mustNewRequest(t, http.MethodGet, "/?file=/var/run/secrets/path/to/file", nil),
			expectErr: true,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/", tt.controller)
			handler := waffleHttp.WafMiddleware(mux)

			waffle.Start()

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tt.req)

			if tt.expectErr {
				assert.Equal(t, http.StatusForbidden, rr.Code)
				return
			}

			assert.Equal(t, http.StatusOK, rr.Code)
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
