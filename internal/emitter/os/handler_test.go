package os_test

import (
	"context"
	"testing"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/os"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectFileOperation(t *testing.T) {
	t.Parallel()

	require.NoError(t, waffle.Start())

	testCases := map[string]struct {
		ctx       context.Context
		filePath  string
		expectErr bool
	}{
		"when through http operation and non-attack request": {
			ctx:       buildHttpOperationCtx(t),
			filePath:  "file.txt",
			expectErr: false,
		},
		"when through http operation and attack request": {
			ctx:       buildHttpOperationCtx(t),
			filePath:  "/var/run/secrets/kubernetes.io/serviceaccount/token",
			expectErr: true,
		},
		"when not through http operation": {
			ctx:       context.Background(),
			filePath:  "file.txt",
			expectErr: false,
		},
		"not through http operation and attack request": {
			ctx:       context.Background(),
			filePath:  "/var/run/secrets/kubernetes.io/serviceaccount/token",
			expectErr: true,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := os.ProtectFileOperation(tt.ctx, tt.filePath)
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
