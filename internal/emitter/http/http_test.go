package http_test

import (
	"net/http"
	"testing"

	httpEmitter "github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildFullURL(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		request http.Request
		want    string
	}{
		"when request has no query values": {
			request: mustHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource"),
			want:    "http://example.com/path/to/resource",
		},
		"when request has query values": {
			request: mustHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource?q=1"),
			want:    "http://example.com/path/to/resource?q=1",
		},
		"when request has multiple query values": {
			request: mustHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource?q=1&q=2"),
			want:    "http://example.com/path/to/resource?q=1&q=2",
		},
		"when request has port number": {
			request: mustHttpRequest(t, http.MethodGet, "http://example.com:8080/path/to/resource"),
			want:    "http://example.com:8080/path/to/resource",
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := httpEmitter.BuildFullURL(&tt.request)
			assert.Equal(t, tt.want, actual)
		})
	}
}

func mustHttpRequest(t *testing.T, method, url string) http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		require.NoError(t, err)
	}

	return *req
}
