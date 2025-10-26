package http_test

import (
	"context"
	"io"
	stdhttp "net/http"
	"testing"

	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/contrib/net/http"
	emitterHttp "github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapClient(t *testing.T) {
	t.Parallel()
	waffle.Start()

	testCases := map[string]struct {
		ctx       context.Context
		url       string
		expectErr bool
	}{
		"when through http operation and non-attack request": {
			ctx:       buildHttpOperationCtx(t),
			url:       "https://example.com",
			expectErr: false,
		},
		"when through http operation and attack request": {
			ctx:       buildHttpOperationCtx(t),
			url:       "http://169.254.169.254",
			expectErr: true,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := http.WrapClient(stdhttp.DefaultClient)
			req, _ := stdhttp.NewRequestWithContext(tt.ctx, "GET", tt.url, nil)

			resp, err := c.Do(req)
			if tt.expectErr {
				assert.Error(t, err)

				var secErr *waf.SecurityBlockingError
				assert.ErrorAs(t, err, &secErr)
				return
			}

			assert.NoError(t, err)

			defer resp.Body.Close()

			assert.Equal(t, 200, resp.StatusCode)

			b, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(b), "Example Domain")
		})
	}
}

func buildHttpOperationCtx(t *testing.T) context.Context {
	t.Helper()

	_, ctx := emitterHttp.StartHTTPRequestHandlerOperation(context.Background(), emitterHttp.HTTPRequestHandlerOperationArg{})
	return ctx
}
