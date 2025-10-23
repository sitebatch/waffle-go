package response_test

import (
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go/handler/response"
	"github.com/stretchr/testify/assert"
)

func TestBlockResponseHandler(t *testing.T) {
	testCases := map[string]struct {
		acceptHeader string
		expected     string
	}{
		"json response": {
			acceptHeader: "application/json",
			expected:     "{\"error\": \"access denied.",
		},
		"html response": {
			acceptHeader: "text/html",
			expected:     "<title>Access Denied</title>",
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", tt.acceptHeader)
			w := httptest.NewRecorder()

			response.BlockResponseHandler().ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), tt.expected)
		})
	}
}

func TestSetBlockResponseTemplateHTML(t *testing.T) {
	customResponseHTML := []byte("<html><meta><title>Custom Access Denied</title></meta></html>")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	response.SetBlockResponseTemplateHTML(customResponseHTML)

	response.BlockResponseHandler().ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), string(customResponseHTML))
}

func TestSetBlockResponseTemplateJSON(t *testing.T) {
	customResponseJSON := []byte("{\"error\": \"Custom Access Denied\"}")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	response.SetBlockResponseTemplateJSON(customResponseJSON)

	response.BlockResponseHandler().ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), string(customResponseJSON))
}
