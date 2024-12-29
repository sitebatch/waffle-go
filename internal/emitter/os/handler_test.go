package os_test

import (
	"context"
	"testing"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/internal/action"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/os"
	"github.com/stretchr/testify/assert"
)

func TestProtectFileOperation(t *testing.T) {
	t.Parallel()

	waffle.Start()

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
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := os.ProtectFileOperation(tt.ctx, tt.filePath)
			if tt.expectErr {
				assert.Error(t, err)

				var berr *action.BlockError
				assert.ErrorAs(t, err, &berr)
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
