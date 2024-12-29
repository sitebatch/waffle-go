package operation_test

import (
	"context"
	"testing"

	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/stretchr/testify/assert"
)

type httpRequestOperation struct {
	operation.Operation
}

type httpRequestOperationArg struct{}
type httpRequestOperationResult struct{}

func (httpRequestOperationArg) IsArgOf(httpRequestOperation)       {}
func (httpRequestOperationResult) IsResultOf(httpRequestOperation) {}

func TestNewRootOperation(t *testing.T) {
	t.Parallel()

	op := operation.NewRootOperation()
	assert.NotEmpty(t, op.GetID())
	assert.Nil(t, op.Parent())
}

func TestNewOperation(t *testing.T) {
	t.Parallel()

	root := operation.NewRootOperation()
	op := operation.NewOperation(root)
	assert.NotEmpty(t, op.GetID())
	assert.Equal(t, root, op.Parent())
}

func TestFindOperationFromContext(t *testing.T) {
	t.Parallel()

	op := httpRequestOperation{
		Operation: operation.NewOperation(nil),
	}

	ctx := context.Background()
	ctx = operation.StartAndRegisterOperation(ctx, op, &httpRequestOperationArg{})

	foundOp, found := operation.FindOperationFromContext(ctx)
	assert.True(t, found)
	assert.Equal(t, op, foundOp)
}

func TestFindOperation(t *testing.T) {
	t.Parallel()

	rootOp := operation.NewRootOperation()
	operation.InitRootOperation(rootOp)

	ctx := context.Background()
	entryOperation, ctx := StartDummyOperation(ctx)

	httpOp := httpRequestOperation{
		Operation: operation.NewOperation(entryOperation),
	}
	ctx = operation.StartAndRegisterOperation(ctx, httpOp, &httpRequestOperationArg{})

	foundOp, found := operation.FindOperation[dummyOperation](ctx)
	assert.True(t, found)
	assert.Equal(t, entryOperation, foundOp)
}

func TestOnStart(t *testing.T) {
	t.Parallel()

	rootOp := operation.NewRootOperation()

	var called bool

	httpRequestListener := func(c *bool) operation.EventListener[httpRequestOperation, httpRequestOperationArg] {
		return func(op httpRequestOperation, arg httpRequestOperationArg) {
			called = true
		}
	}(&called)

	operation.OnStart(rootOp, httpRequestListener)

	operation.InitRootOperation(rootOp)

	ctx := context.Background()
	entryOperation, ctx := StartDummyOperation(ctx)

	httpOp := httpRequestOperation{
		Operation: operation.NewOperation(entryOperation),
	}

	operation.StartAndRegisterOperation(ctx, httpOp, httpRequestOperationArg{})

	assert.True(t, called)
}

func TestOnFinish(t *testing.T) {
	t.Parallel()

	rootOp := operation.NewRootOperation()

	var called bool

	finish := func(c *bool) operation.EventListener[httpRequestOperation, httpRequestOperationResult] {
		return func(op httpRequestOperation, arg httpRequestOperationResult) {
			called = true
		}
	}(&called)

	operation.OnFinish(rootOp, finish)

	operation.InitRootOperation(rootOp)

	ctx := context.Background()
	entryOperation, _ := StartDummyOperation(ctx)

	httpOp := httpRequestOperation{
		Operation: operation.NewOperation(entryOperation),
	}

	operation.FinishOperation(httpOp, httpRequestOperationResult{})

	assert.True(t, called)
}

type dummyOperation struct {
	operation.Operation
}

type dummyOperationArg struct{}

func (dummyOperationArg) IsArgOf(*dummyOperation) {}

func StartDummyOperation(ctx context.Context) (*dummyOperation, context.Context) {
	parent, _ := operation.FindOperationFromContext(ctx)
	op := &dummyOperation{
		Operation: operation.NewOperation(parent),
	}

	return op, operation.StartAndRegisterOperation(ctx, op, dummyOperationArg{})
}
