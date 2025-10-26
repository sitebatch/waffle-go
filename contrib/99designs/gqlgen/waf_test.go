package gqlgen_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/contrib/99designs/gqlgen"
	"github.com/sitebatch/waffle-go/contrib/99designs/gqlgen/testserver/graph"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vektah/gqlparser/v2/ast"
)

func TestWafMiddleware(t *testing.T) {
	mux := http.NewServeMux()

	gqlHandler := func() http.HandlerFunc {
		srv := handler.New(graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{}}))
		srv.AddTransport(transport.Options{})
		srv.AddTransport(transport.GET{})
		srv.AddTransport(transport.POST{})

		srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))

		srv.Use(gqlgen.WafMiddleware{})
		srv.Use(extension.Introspection{})
		srv.Use(extension.AutomaticPersistedQuery{
			Cache: lru.New[string](100),
		})

		return func(w http.ResponseWriter, r *http.Request) {
			srv.ServeHTTP(w, r)
		}
	}

	mux.Handle("/query", gqlHandler())
	handler := waffleHttp.WafMiddleware(mux)

	testCases := map[string]struct {
		query        string
		variables    map[string]interface{}
		waffleRule   []byte
		expectStatus int
		expectBody   string
	}{
		"query": {
			query:        `query { todos { id text done user { id name } } }`,
			variables:    nil,
			expectStatus: http.StatusOK,
			expectBody:   `{"data":{"todos":[`,
		},
		"query with variables": {
			query: `query SearchTodoWithVariables($id: ID!, $text: String!) { searchTodo(id: $id, text: $text) { id text done user { id name } } }`,
			variables: map[string]interface{}{
				"id":   "1",
				"text": "Sample Todo",
			},
			expectStatus: http.StatusOK,
			expectBody:   `{"data":{"searchTodo":[`,
		},
		"mutation": {
			query: `mutation CreateTodo($input: NewTodo!) { createTodo(input: $input) { id text done user { id name } } }`,
			variables: map[string]interface{}{
				"input": map[string]interface{}{
					"text":   "Sample Todo",
					"userId": "1",
				},
			},
			expectStatus: http.StatusOK,
			expectBody:   `{"data":{"createTodo":{`,
		},
		"blocked via http.request.body": {
			query: `query SearchTodoWithVariables($id: ID!, $text: String!) { searchTodo(id: $id, text: $text) { id text done user { id name } } }`,
			variables: map[string]interface{}{
				"id":   "1",
				"text": "<script>alert('XSS')</script>",
			},
			waffleRule:   blockRuleHttpRequestBody,
			expectStatus: http.StatusForbidden,
			expectBody:   `{"error": "access denied. Sorry, you cannnot access this resource. Please contact the customer support."}`,
		},
		"blocked via graphql.request.body": {
			query: `query SearchTodoWithVariables($id: ID!, $text: String!) { searchTodo(id: $id, text: $text) { id text done user { id name } } }`,
			variables: map[string]interface{}{
				"id":   "1",
				"text": "<script>alert(1)</script>",
			},
			waffleRule:   blockRuleGraphQLRequestVariables,
			expectStatus: http.StatusForbidden,
			expectBody:   `{"error": "access denied. Sorry, you cannnot access this resource. Please contact the customer support."}`,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			var body interface{}

			if tt.variables == nil {
				body = map[string]interface{}{
					"query": tt.query,
				}
			} else {
				body = map[string]interface{}{
					"query":     tt.query,
					"variables": tt.variables,
				}
			}
			bodyBytes, err := json.Marshal(body)
			require.NoError(t, err)

			waffle.Start(waffle.WithRule(tt.waffleRule))

			req, err := http.NewRequest("POST", "/query", bytes.NewBuffer(bodyBytes))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectBody)
		})
	}
}

var blockRuleHttpRequestBody = []byte(`
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
      		        "target": "http.request.body"
      		      }
      		    ]
      		  }
      		]
    	}
	]
}`)

var blockRuleGraphQLRequestVariables = []byte(`
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
      		        "target": "graphql.request.variables"
      		      }
      		    ]
      		  }
      		]
    	}
	]
}`)
