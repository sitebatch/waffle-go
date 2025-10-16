package http_test

import (
	"bytes"
	"io"
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
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource", nil),
			want:    "http://example.com/path/to/resource",
		},
		"when request has query values": {
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource?q=1", nil),
			want:    "http://example.com/path/to/resource?q=1",
		},
		"when request has multiple query values": {
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource?q=1&q=2", nil),
			want:    "http://example.com/path/to/resource?q=1&q=2",
		},
		"when request has port number": {
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com:8080/path/to/resource", nil),
			want:    "http://example.com:8080/path/to/resource",
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := httpEmitter.BuildFullURL(&tt.request)
			assert.Equal(t, tt.want, actual)
		})
	}
}

func TestBuildHttpRequestHandlerOperationArg(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		request  http.Request
		expected httpEmitter.HTTPRequestHandlerOperationArg
	}{
		"when request has no query values": {
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource", nil),
			expected: httpEmitter.HTTPRequestHandlerOperationArg{
				URL:         "http://example.com/path/to/resource",
				Path:        "/path/to/resource",
				Headers:     map[string][]string{},
				QueryValues: map[string][]string{},
				RawBody:     nil,
				Body:        map[string][]string{},
				ClientIP:    "",
			},
		},
		"when request has query values": {
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource?q=1", nil),
			expected: httpEmitter.HTTPRequestHandlerOperationArg{
				URL:         "http://example.com/path/to/resource?q=1",
				Path:        "/path/to/resource",
				Headers:     map[string][]string{},
				QueryValues: map[string][]string{"q": {"1"}},
				RawBody:     nil,
				Body:        map[string][]string{},
				ClientIP:    "",
			},
		},
		"when request has multiple query values": {
			request: mustNewHttpRequest(t, http.MethodGet, "http://example.com/path/to/resource?q=1&q=2", nil),
			expected: httpEmitter.HTTPRequestHandlerOperationArg{
				URL:         "http://example.com/path/to/resource?q=1&q=2",
				Path:        "/path/to/resource",
				Headers:     map[string][]string{},
				QueryValues: map[string][]string{"q": {"1", "2"}},
				RawBody:     nil,
				Body:        map[string][]string{},
				ClientIP:    "",
			},
		},
		"when request has body": {
			request: mustNewHttpRequest(
				t,
				http.MethodPost,
				"http://example.com/path/to/resource?q=1",
				bytes.NewBuffer([]byte("key=value1&key=value2")),
				withHeader("Content-Type", "application/x-www-form-urlencoded"),
			),
			expected: httpEmitter.HTTPRequestHandlerOperationArg{
				URL:         "http://example.com/path/to/resource?q=1",
				Path:        "/path/to/resource",
				Headers:     map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
				QueryValues: map[string][]string{"q": {"1"}},
				RawBody:     []byte("key=value1&key=value2"),
				Body:        map[string][]string{"key": {"value1", "value2"}},
				ClientIP:    "",
			},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := httpEmitter.BuildHttpRequestHandlerOperationArg(&tt.request)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

type httpRequestOptions func(*http.Request)

func withHeader(key, value string) httpRequestOptions {
	return func(r *http.Request) {
		r.Header.Set(key, value)
	}
}

func mustNewHttpRequest(t *testing.T, method, url string, body io.Reader, opts ...httpRequestOptions) http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		require.NoError(t, err)
	}

	for _, opt := range opts {
		opt(req)
	}

	return *req
}
