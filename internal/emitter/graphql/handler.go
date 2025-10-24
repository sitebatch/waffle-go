package graphql

import (
	"context"

	"github.com/jeremywohl/flatten"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type GraphqlRequestHandlerOperation struct {
	operation.Operation
	*waf.WafOperation
}

type GraphqlRequestHandlerOperationArg struct {
	RawQuery      string
	OperationName string
	Variables     map[string][]string
}

type GraphqlRequestHandlerOperationResult struct {
	BlockErr error
}

func (GraphqlRequestHandlerOperationArg) IsArgOf(*GraphqlRequestHandlerOperation)        {}
func (*GraphqlRequestHandlerOperationResult) IsResultOf(*GraphqlRequestHandlerOperation) {}

func StartGraphQLRequestHandlerOperation(ctx context.Context, args GraphqlRequestHandlerOperationArg) (*GraphqlRequestHandlerOperation, context.Context) {
	parent, _ := operation.FindOperationFromContext(ctx)

	var wafop *waf.WafOperation
	if parentOp, ok := parent.(*http.HTTPRequestHandlerOperation); ok {
		wafop = parentOp.WafOperation
	} else {
		wafop, _ = waf.InitializeWafOperation(ctx)
	}

	op := &GraphqlRequestHandlerOperation{
		Operation:    operation.NewOperation(parent),
		WafOperation: wafop,
	}

	return op, operation.StartAndSetOperation(ctx, op, args)
}

func (op *GraphqlRequestHandlerOperation) Finish(res *GraphqlRequestHandlerOperationResult) {
	operation.FinishOperation(op, res)
}

func BuildGraphqlRequestHandlerOperationArg(
	rawQuery string,
	operationName string,
	variables map[string]interface{},
) GraphqlRequestHandlerOperationArg {
	var graphqlVariables map[string][]string

	flat, err := flatten.Flatten(variables, "", flatten.DotStyle)
	if err != nil {
		graphqlVariables = map[string][]string{}
	} else {
		graphqlVariables = make(map[string][]string)
		for k, v := range flat {
			if s, ok := v.(string); ok {
				graphqlVariables[k] = []string{s}
			}
		}
	}

	return GraphqlRequestHandlerOperationArg{
		RawQuery:      rawQuery,
		OperationName: operationName,
		Variables:     graphqlVariables,
	}
}
