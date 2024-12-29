package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go"
	httpHandler "github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/stretchr/testify/require"
)

func TestWrapHandler(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		req          *http.Request
		expectedCode int
	}{
		"not attack request": {
			req:          mustNewRequest(t, http.MethodGet, "/", nil),
			expectedCode: http.StatusOK,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fn := func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello"))
			}

			mux := http.NewServeMux()
			mux.Handle("/", http.HandlerFunc(fn))

			waffle.Start()

			handler := httpHandler.WrapHandler(mux, httpHandler.Options{})

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tc.req)

			require.Equal(t, tc.expectedCode, rr.Code)
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
