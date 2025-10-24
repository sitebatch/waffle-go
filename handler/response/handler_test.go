package response_test

import (
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go/handler/response"
	"github.com/stretchr/testify/assert"
)

func TestBlockResponseHandler(t *testing.T) {
	testCases := map[string]struct {
		contentType  string
		acceptHeader string
		expected     string
	}{
		"return JSON response, when Accept header is set to application/json": {
			contentType:  "text/html",
			acceptHeader: "application/json",
			expected:     "{\"error\": \"access denied.",
		},
		"return JSON response, when Content-Type header is set to application/json": {
			contentType:  "application/json",
			acceptHeader: "*/*",
			expected:     "{\"error\": \"access denied.",
		},
		"return HTML response, when Accept header is set to text/html": {
			contentType:  "",
			acceptHeader: "text/html",
			expected:     "<title>Access Denied</title>",
		},
		"return HTML response, when Content-Type header is set to text/html": {
			contentType:  "text/html",
			acceptHeader: "*/*",
			expected:     "<title>Access Denied</title>",
		},
		"default to HTML response": {
			contentType:  "text/plain",
			acceptHeader: "*/*",
			expected:     "<title>Access Denied</title>",
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", tt.acceptHeader)
			w := httptest.NewRecorder()

			response.BlockResponseHandler(tt.contentType).ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), tt.expected)
		})
	}
}

func TestSetBlockResponseTemplateHTML(t *testing.T) {
	customResponseHTML := []byte("<html><meta><title>Custom Access Denied</title></meta></html>")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	response.SetBlockResponseTemplateHTML(customResponseHTML)

	response.BlockResponseHandler("text/html").ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), string(customResponseHTML))
}

func TestSetBlockResponseTemplateJSON(t *testing.T) {
	customResponseJSON := []byte("{\"error\": \"Custom Access Denied\"}")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	response.SetBlockResponseTemplateJSON(customResponseJSON)

	response.BlockResponseHandler("application/json").ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), string(customResponseJSON))
}
