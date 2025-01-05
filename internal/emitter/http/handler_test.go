package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go"
	httpHandler "github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/os"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapHandler(t *testing.T) {
	defaultFn := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("Hello")) }

	testCases := map[string]struct {
		req                *http.Request
		waffleRule         []byte
		fn                 func(w http.ResponseWriter, r *http.Request)
		expectedCode       int
		expectResponseBody string
	}{
		"not blocked request": {
			req:                mustNewRequest(t, http.MethodGet, "/", nil),
			expectedCode:       http.StatusOK,
			expectResponseBody: "Hello",
		},
		"blocked request": {
			req:                mustNewRequest(t, http.MethodGet, "/?q=<script>alert(1)</script>", nil),
			waffleRule:         blockRuleHttpRequest,
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "<title>Access Denied</title>",
		},
		"If the operation is blocked by subsequent processing of the middleware": {
			req: mustNewRequest(t, http.MethodGet, "/", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				blockOperation(t, r.Context())
			},
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "<title>Access Denied</title>",
		},
		"If there is already a write to the response, the blocked response will not be returned": {
			req: mustNewRequest(t, http.MethodGet, "/", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				blockOperation(t, r.Context())
				w.Write([]byte("some errors"))
			},
			expectedCode:       http.StatusOK,
			expectResponseBody: "some errors",
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			if tt.fn == nil {
				tt.fn = defaultFn
			}

			mux := http.NewServeMux()
			mux.Handle("/", http.HandlerFunc(tt.fn))

			if tt.waffleRule != nil {
				waffle.Start(waffle.WithOverrideRules(tt.waffleRule))
			} else {
				waffle.Start()
			}

			handler := httpHandler.WrapHandler(mux, httpHandler.Options{})

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tt.req)

			assert.Equal(t, tt.expectedCode, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectResponseBody)
		})
	}
}

func mustNewRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		require.NoError(t, err)
	}

	return req
}

var blockRuleHttpRequest = []byte(`
{
	"version": "0.1",
	"rules": [
		{
      		"id": "xss-attempts",
      		"name": "XSS attempts",
      		"tags": ["xss", "attack attempts"],
      		"action": "block",
      		"conditions": [
      		  {
      		    "inspector": "libinjection_xss",
      		    "inspect_target": [
      		      {
      		        "target": "http.request.query"
      		      }
      		    ]
      		  }
      		]
    	}
	]
}`)

func blockOperation(t *testing.T, ctx context.Context) {
	t.Helper()

	parent, _ := operation.FindOperationFromContext(ctx)
	var wafop *waf.WafOperation
	if parentOp, ok := parent.(*httpHandler.HTTPRequestHandlerOperation); ok {
		wafop = parentOp.WafOperation
	}
	require.NotNil(t, wafop)

	op := &os.FileOperation{
		Operation:    operation.NewOperation(parent),
		WafOperation: wafop,
	}
	operation.StartOperation(op, os.FileOperationArg{Path: "/etc/passwd"})

	res := &os.FileOperationResult{}
	operation.FinishOperation(op, res)
}
