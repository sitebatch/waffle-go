package action_test

import (
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go/action"
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
		tt := tt

		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", tt.acceptHeader)
			w := httptest.NewRecorder()

			action.BlockResponseHandler().ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), tt.expected)
		})
	}
}

func TestRegisterBlockResponseTemplateHTML(t *testing.T) {
	testCases := map[string]struct {
		customResponseHTML []byte
		expected           string
	}{
		"custom response": {
			customResponseHTML: []byte("<html><meta><title>Custom Access Denied</title></meta></html>"),
			expected:           "<title>Custom Access Denied</title>",
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()

			action.RegisterBlockResponseTemplateHTML(tt.customResponseHTML)

			action.BlockResponseHandler().ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), tt.expected)
		})
	}
}

func TestRegisterBlockResponseTemplateJSON(t *testing.T) {
	testCases := map[string]struct {
		customResponseJSON []byte
		expected           string
	}{
		"custom response": {
			customResponseJSON: []byte("{\"error\": \"Custom Access Denied\"}"),
			expected:           "{\"error\": \"Custom Access Denied\"}",
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			action.RegisterBlockResponseTemplateJSON(tt.customResponseJSON)

			action.BlockResponseHandler().ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), tt.expected)
		})
	}
}
