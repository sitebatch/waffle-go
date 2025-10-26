package http_test

import (
	"bytes"
	"context"
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
	defaultFn := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("Hello")) }

	testCases := map[string]struct {
		req                http.Request
		waffleRule         []byte
		fn                 func(w http.ResponseWriter, r *http.Request)
		expectedCode       int
		expectResponseBody string
	}{
		"not blocked request (GET)": {
			req:                mustNewHttpRequest(t, http.MethodGet, "/", nil),
			expectedCode:       http.StatusOK,
			expectResponseBody: "Hello",
		},
		"not blocked request (POST)": {
			req:                mustNewHttpRequest(t, http.MethodPost, "/", bytes.NewBuffer([]byte("key=value"))),
			expectedCode:       http.StatusOK,
			expectResponseBody: "Hello",
		},
		"blocked request (GET)": {
			req:                mustNewHttpRequest(t, http.MethodGet, "/?q=<script>alert(1)</script>", nil),
			waffleRule:         blockRuleHttpRequest,
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "request blocked",
		},
		"blocked request (POST)": {
			req:                mustNewHttpRequest(t, http.MethodPost, "/?q=value", bytes.NewBuffer([]byte("key=<script>alert(1)</script>")), withHeader("Content-Type", "application/x-www-form-urlencoded")),
			waffleRule:         blockRuleHttpRequest,
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "request blocked",
		},
		"when blocked after middleware": {
			req: mustNewHttpRequest(t, http.MethodGet, "/", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				blockOperation(t, r.Context())
			},
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "request blocked",
		},
		"when blocked after middleware and overwrites any existing response body": {
			req: mustNewHttpRequest(t, http.MethodGet, "/", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				blockOperation(t, r.Context())
				_, _ = w.Write([]byte("some errors"))
			},
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "request blocked",
		},
		"when blocked after middleware and overwrites any existing response status header and body": {
			req: mustNewHttpRequest(t, http.MethodGet, "/", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				blockOperation(t, r.Context())
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("some errors"))
			},
			expectedCode:       http.StatusForbidden,
			expectResponseBody: "request blocked",
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			if tt.fn == nil {
				tt.fn = defaultFn
			}

			mux := http.NewServeMux()
			mux.Handle("/", http.HandlerFunc(tt.fn))

			waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))

			if tt.waffleRule != nil {
				require.NoError(t, waffle.Start(waffle.WithRule(tt.waffleRule)))
			} else {
				require.NoError(t, waffle.Start())
			}

			handler := httpHandler.WrapHandler(mux, httpHandler.Options{})

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, &tt.req)

			assert.Equal(t, tt.expectedCode, rr.Code)
			assert.Equal(t, tt.expectResponseBody, rr.Body.String())
		})
	}
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
      		      },
				  {
				  	"target": "http.request.body"
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
