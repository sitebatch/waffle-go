package parser_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sitebatch/waffle-go/internal/emitter/http/parser"
	"github.com/stretchr/testify/assert"
)

func TestFormParser_Parse(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body     string
		expected map[string][]string
	}{
		"simple": {
			body: "key=value",
			expected: map[string][]string{
				"key": {"value"},
			},
		},
		"multiple": {
			body: "key1=value1&key2=value2",
			expected: map[string][]string{
				"key1": {"value1"},
				"key2": {"value2"},
			},
		},
		"array": {
			body: "key=value1&key=value2",
			expected: map[string][]string{
				"key": {"value1", "value2"},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			result, err := parser.ParseHTTPRequestBody(r)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMultipartParser_Parse(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body     string
		expected map[string][]string
	}{
		"success": {
			body: `--boundary
Content-Disposition: form-data; name="key"

value
--boundary--`,
			expected: map[string][]string{
				"key": {"value"},
			},
		},
		"multiple": {
			body: `--boundary
Content-Disposition: form-data; name="key1"

value1
--boundary
Content-Disposition: form-data; name="key2"

value2
--boundary--`,
			expected: map[string][]string{
				"key1": {"value1"},
				"key2": {"value2"},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

			result, err := parser.ParseHTTPRequestBody(r)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}
