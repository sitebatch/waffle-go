package graphql_test

import (
	"fmt"
	"testing"

	"github.com/sitebatch/waffle-go/internal/emitter/graphql"
	"github.com/stretchr/testify/assert"
)

func TestBuildGraphqlRequestHandlerOperationArg(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		variables map[string]interface{}
		expect    map[string][]string
	}{
		{
			variables: nil,
			expect:    map[string][]string{},
		},
		{
			variables: map[string]interface{}{
				"key": "value",
			},
			expect: map[string][]string{
				"key": {"value"},
			},
		},
		{
			variables: map[string]interface{}{
				"key":  "value",
				"key2": "value2",
			},
			expect: map[string][]string{
				"key":  {"value"},
				"key2": {"value2"},
			},
		},
		{
			variables: map[string]interface{}{
				"input": map[string]interface{}{
					"text":   "Sample Todo",
					"userId": "1",
				},
			},
			expect: map[string][]string{
				"input.text":   {"Sample Todo"},
				"input.userId": {"1"},
			},
		},
	}

	for i, tt := range testCases {
		tt := tt

		t.Run(fmt.Sprintf("testcase #%d", i), func(t *testing.T) {
			t.Parallel()

			arg := graphql.BuildGraphqlRequestHandlerOperationArg("", "", tt.variables)
			assert.Equal(t, tt.expect, arg.Variables)
		})
	}

}
