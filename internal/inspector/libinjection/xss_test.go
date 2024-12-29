package libinjection_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector/libinjection"
	"github.com/stretchr/testify/assert"
)

func TestIsXSSPayload(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		payload string
		detect  bool
	}{
		{
			payload: "<script>alert('xss')</script>",
			detect:  true,
		},
		{
			payload: "<img src=x onerror=alert('xss')>",
			detect:  true,
		},
		{
			payload: "<svg onload=alert('xss')>",
			detect:  true,
		},
		{
			payload: "<body onload=alert('xss')>",
			detect:  true,
		},
		{
			payload: "<iframe src=javascript:alert('xss')>",
			detect:  true,
		},
		{
			payload: "<script",
			detect:  true,
		},
		{
			payload: "script",
			detect:  false,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.payload, func(t *testing.T) {
			t.Parallel()

			if tc.detect {
				assert.Error(t, libinjection.IsXSSPayload(tc.payload))
			} else {
				assert.NoError(t, libinjection.IsXSSPayload(tc.payload))
			}
		})
	}
}
