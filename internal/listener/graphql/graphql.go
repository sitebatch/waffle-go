package graphql

import (
	"github.com/sitebatch/waffle-go/internal/emitter/graphql"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/inspector"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/operation"
)

type GraphqlSecurity struct{}

func (h *GraphqlSecurity) Name() string {
	return "graphql_security"
}

func NewGraphqlSecurity(rootOp operation.Operation) (listener.Listener, error) {
	graphqlSec := &GraphqlSecurity{}

	operation.OnStart(rootOp, graphqlSec.OnRequest)
	operation.OnFinish(rootOp, graphqlSec.OnFinish)
	return graphqlSec, nil
}

func (graphqlSec *GraphqlSecurity) OnRequest(op *graphql.GraphqlRequestHandlerOperation, args graphql.GraphqlRequestHandlerOperationArg) {
	op.Run(
		op,
		*inspector.NewInspectDataBuilder(op.OperationContext()).
			WithGraphQLRequestRawQuery(args.RawQuery).
			WithGraphQLRequestOperationName(args.OperationName).
			WithGraphQLRequestVariables(args.Variables).
			Build(),
	)
}

func (graphqlSec *GraphqlSecurity) OnFinish(op *graphql.GraphqlRequestHandlerOperation, res *graphql.GraphqlRequestHandlerOperationResult) {
	result := &waf.WafOperationResult{}
	op.FinishInspect(op, result)

	if result.IsBlock() {
		res.BlockErr = result.BlockErr
	}
}
