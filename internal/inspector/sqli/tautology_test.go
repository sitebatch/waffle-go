package sqli_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/internal/inspector/sqli"
	"github.com/stretchr/testify/assert"
)

func TestIsWhereTautologyFull(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		query     string
		expect    bool
		expectErr bool
	}{
		{
			query:     "SELECT * FROM users WHERE 1=1",
			expect:    true,
			expectErr: false,
		},
		{
			query:     "SELECT * FROM users WHERE TRUE",
			expect:    false,
			expectErr: false,
		},
		{
			query:     "SELECT * FROM users WHERE id = 1",
			expect:    false,
			expectErr: false,
		},
		{
			query:     "SELECT * FROM users WHERE id = 1 AND name = 'admin'",
			expect:    false,
			expectErr: false,
		},
		{
			query:     "SELECT * FROM users WHERE id = ? AND name = ?",
			expect:    false,
			expectErr: false,
		},
		{
			query:     "SELECT * FROM users WHERE id = 1 OR 1=1",
			expect:    true,
			expectErr: false,
		},
		{
			query:     "SELECT * FROM users email = ? AND password = ?;",
			expect:    false,
			expectErr: false,
		},
		// {
		// 	query:     "SELECT * FROM users WHERE id = 1 OR TRUE",
		// 	expect:    true,
		// 	expectErr: false,
		// },
	}

	for _, tt := range testCases {
		tt := tt

		t.Run(tt.query, func(t *testing.T) {
			t.Parallel()

			got, err := sqli.IsWhereTautologyFull(tt.query)
			if tt.expectErr {
				assert.Error(t, err)
			}

			assert.Equal(t, tt.expect, got)
		})
	}
}
