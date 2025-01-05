package gqlgen

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/errcode"
	graphqlEmitter "github.com/sitebatch/waffle-go/internal/emitter/graphql"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type (
	WafMiddleware struct{}
)

var _ interface {
	graphql.OperationInterceptor
	graphql.HandlerExtension
} = &WafMiddleware{}

func (a WafMiddleware) ExtensionName() string {
	return "Waffle Waf Middleware"
}

func (a WafMiddleware) Validate(_ graphql.ExecutableSchema) error {
	return nil
}

func (a WafMiddleware) InterceptOperation(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
	opCtx := graphql.GetOperationContext(ctx)

	op, wafCtx := graphqlEmitter.StartGraphQLRequestHandlerOperation(
		ctx, graphqlEmitter.BuildGraphqlRequestHandlerOperationArg(
			opCtx.RawQuery,
			opCtx.OperationName,
			opCtx.Variables,
		),
	)

	responseOperationHandler := next(wafCtx)
	return func(ctx context.Context) *graphql.Response {
		var result graphqlEmitter.GraphqlRequestHandlerOperationResult
		op.Finish(&result)

		if result.BlockErr != nil {
			err := gqlerror.Errorf("RequestBlocked")
			errcode.Set(err, "REQUEST_BLOCKED")
			return &graphql.Response{
				Errors: gqlerror.List{
					err,
				},
			}
		}

		return responseOperationHandler(ctx)
	}
}

func (a WafMiddleware) InterceptField(ctx context.Context, next graphql.Resolver) (res interface{}, err error) {
	return next(ctx)
}
