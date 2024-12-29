package sqli_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector/sqli"
	"github.com/stretchr/testify/assert"
)

func TestIsQueryCommentInjection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		query       string
		expectError bool
	}{
		{
			query:       "SELECT * FROM users WHERE id = 1 -- comment",
			expectError: false,
		},
		{
			query:       "SELECT * FROM /* comment */ users WHERE id = 1 -- comment SELECT 1",
			expectError: false,
		},
		{
			query:       "SELECT * FROM users WHERE id = 1",
			expectError: false,
		},
		{
			query:       "SELECT * FROM users WHERE name = 'test' # SELECT 1",
			expectError: true,
		},
		{
			query:       "SELECT * FROM users WHERE name = 'test' -- AND password = ?",
			expectError: true,
		},
		{
			query:       "SELECT * FROM users WHERE id = 1 -- AND password = ?",
			expectError: true,
		},
		{
			query:       "SELECT * FROM users email = ? AND password = ?;",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.query, func(t *testing.T) {
			t.Parallel()

			err := sqli.IsQueryCommentInjection(tc.query)
			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
