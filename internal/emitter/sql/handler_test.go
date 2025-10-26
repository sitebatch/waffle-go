package sql_test

import (
	"context"
	"testing"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/sql"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
)

func TestProtectSQLOperation(t *testing.T) {
	t.Parallel()

	waffle.Start()

	testCases := map[string]struct {
		ctx       context.Context
		query     string
		expectErr bool
	}{
		"when through http operation and non-attack request": {
			ctx:       buildHttpOperationCtx(t),
			query:     "SELECT * FROM users",
			expectErr: false,
		},
		"when through http operation and attack request": {
			ctx:       buildHttpOperationCtx(t),
			query:     "SELECT * FROM users WHERE id = '1' OR 1=1--",
			expectErr: true,
		},
		"when not through http operation": {
			ctx:       context.Background(),
			query:     "SELECT * FROM users",
			expectErr: false,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := sql.ProtectSQLOperation(tt.ctx, tt.query)
			if tt.expectErr {
				assert.Error(t, err)

				var secErr *waf.SecurityBlockingError
				assert.ErrorAs(t, err, &secErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func buildHttpOperationCtx(t *testing.T) context.Context {
	t.Helper()

	_, ctx := http.StartHTTPRequestHandlerOperation(context.Background(), http.HTTPRequestHandlerOperationArg{})
	return ctx
}
