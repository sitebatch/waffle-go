package parser_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sitebatch/waffle-go/internal/emitter/http/parser"
	"github.com/stretchr/testify/assert"
)

func TestJSONParser_Parse(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body     string
		expected map[string][]string
	}{
		"success": {
			body: `{"key": "value"}`,
			expected: map[string][]string{
				"key": {"value"},
			},
		},
		"nested": {
			body: `{"key": {"nested": "value"}}`,
			expected: map[string][]string{
				"key.nested": {"value"},
			},
		},
		"array": {
			body: `{"key": ["value1", "value2"]}`,
			expected: map[string][]string{
				"key.0": {"value1"},
				"key.1": {"value2"},
			},
		},
		"array_nested": {
			body: `{"key": [{"nested": "value1"}, {"nested": "value2"}]}`,
			expected: map[string][]string{
				"key.0.nested": {"value1"},
				"key.1.nested": {"value2"},
			},
		},
		"array_nested_array": {
			body: `{"key": [{"nested": ["value1", "value2"]}]}`,
			expected: map[string][]string{
				"key.0.nested.0": {"value1"},
				"key.0.nested.1": {"value2"},
			},
		},
		"invalid_json": {
			body:     `{"key": "value"`,
			expected: nil,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(strings.NewReader(tc.body)),
			}

			got, err := parser.ParseHTTPRequestBody(req)
			if tc.expected == nil {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)

			// Ensure the body is still readable
			b, err := io.ReadAll(req.Body)
			assert.NoError(t, err)
			assert.Equal(t, tc.body, string(b))
		})
	}
}
