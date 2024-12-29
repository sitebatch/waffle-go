package libinjection_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector/libinjection"
	"github.com/sitebatch/waffle-go/lib"
	"github.com/stretchr/testify/assert"
)

func TestIsSQLiPayload(t *testing.T) {
	t.Parallel()

	lib.Load()

	testCases := []struct {
		value       string
		expectError bool
	}{
		{
			value:       "test",
			expectError: false,
		},
		{
			value:       "-1' and 1=1 union/* foo */select load_file('/etc/passwd')--",
			expectError: true,
		},
		{
			value:       "test' # ",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			err := libinjection.IsSQLiPayload(tc.value)
			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
