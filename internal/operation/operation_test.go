package operation_test

import (
	"context"
	"testing"

	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/stretchr/testify/assert"
)

func TestNewRootOperation(t *testing.T) {
	t.Parallel()

	op := operation.NewRootOperation()
	assert.NotEmpty(t, op.GetID())
	assert.Len(t, op.GetID(), operation.EventIDLength)
	assert.Nil(t, op.Parent())
}

func TestNewOperation(t *testing.T) {
	rootOp := operation.NewRootOperation()
	assert.False(t, operation.IsRootOperationInitialized())
	operation.InitRootOperation(rootOp)
	assert.True(t, operation.IsRootOperationInitialized())

	parentOp := operation.NewOperation(rootOp)

	testCases := map[string]struct {
		parent     operation.Operation
		wantParent operation.Operation
	}{
		"with nil parent": {
			parent:     nil,
			wantParent: rootOp,
		},
		"with non-nil parent": {
			parent:     parentOp,
			wantParent: parentOp,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := operation.NewOperation(tt.parent)
			assert.NotEmpty(t, op.GetID())
			assert.Len(t, op.GetID(), operation.EventIDLength)
			assert.Equal(t, tt.wantParent, op.Parent())
		})
	}
}

func TestFindOperationFromContext(t *testing.T) {
	t.Parallel()

	httpOp := &httpRequestOperation{
		Operation: operation.NewOperation(nil),
	}
	ctxWithHttpOp := operation.StartAndSetOperation(context.Background(), httpOp, httpRequestOperationArg{})

	testCases := map[string]struct {
		ctx      context.Context
		wantOp   operation.Operation
		wantFind bool
	}{
		"with no operation in context": {
			ctx:      context.Background(),
			wantOp:   nil,
			wantFind: false,
		},
		"with nil context": {
			ctx:      nil,
			wantOp:   nil,
			wantFind: false,
		},
		"with operation in context": {
			ctx:      ctxWithHttpOp,
			wantOp:   httpOp,
			wantFind: true,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gotOp, found := operation.FindOperationFromContext(tt.ctx)
			assert.Equal(t, tt.wantOp, gotOp)
			assert.Equal(t, tt.wantFind, found)
		})
	}
}

func TestFindOperation(t *testing.T) {
	t.Parallel()

	rootOp := operation.NewRootOperation()
	operation.InitRootOperation(rootOp)

	dummyOp, ctx := StartAndSetDummyOperation(context.Background())

	httpOp := &httpRequestOperation{
		Operation: operation.NewOperation(dummyOp),
	}
	ctx = operation.StartAndSetOperation(ctx, httpOp, httpRequestOperationArg{})

	t.Run("find httpRequestOperation from context", func(t *testing.T) {
		t.Parallel()

		foundOp, found := operation.FindOperation[httpRequestOperation](ctx)
		assert.True(t, found)
		assert.Equal(t, httpOp, foundOp)
	})

	t.Run("find dummyOperation from context", func(t *testing.T) {
		t.Parallel()

		foundOp, found := operation.FindOperation[dummyOperation](ctx)
		assert.True(t, found)
		assert.Equal(t, dummyOp, foundOp)
	})

	t.Run("not find non-existing operation from context", func(t *testing.T) {
		t.Parallel()

		type o struct {
			operation.Operation
		}

		foundOp, found := operation.FindOperation[o](ctx)
		assert.False(t, found)
		assert.Nil(t, foundOp)
	})
}

func TestSetOperation(t *testing.T) {
	t.Parallel()

	rootOp := operation.NewRootOperation()
	operation.InitRootOperation(rootOp)

	dummyOp := &dummyOperation{
		Operation: operation.NewOperation(nil),
	}

	ctx := operation.SetOperation(context.Background(), dummyOp)
	foundOp, found := operation.FindOperationFromContext(ctx)
	assert.True(t, found)
	assert.Equal(t, dummyOp, foundOp)
}

func TestStartOperation(t *testing.T) {
	t.Parallel()

	var (
		httpRequestListenerCall int
		dummyListenerCall       int
	)

	httpRequestListener := func(c *int) operation.EventListener[*httpRequestOperation, httpRequestOperationArg] {
		return func(op *httpRequestOperation, arg httpRequestOperationArg) {
			*c++
		}
	}(&httpRequestListenerCall)

	dummyListener := func(c *int) operation.EventListener[*dummyOperation, dummyOperationArg] {
		return func(op *dummyOperation, arg dummyOperationArg) {
			*c++
		}
	}(&dummyListenerCall)

	rootOp := operation.NewRootOperation()
	operation.OnStart(rootOp, httpRequestListener)
	operation.OnStart(rootOp, dummyListener)
	operation.InitRootOperation(rootOp)

	httpOp := &httpRequestOperation{
		Operation: operation.NewOperation(nil),
	}

	assert.Equal(t, 0, httpRequestListenerCall)
	assert.Equal(t, 0, dummyListenerCall)

	operation.StartOperation(httpOp, httpRequestOperationArg{})

	assert.Equal(t, 1, httpRequestListenerCall)
	assert.Equal(t, 0, dummyListenerCall)

	dummyOp := &dummyOperation{
		Operation: operation.NewOperation(httpOp),
	}

	operation.StartOperation(dummyOp, dummyOperationArg{})
	assert.Equal(t, 1, httpRequestListenerCall)
	assert.Equal(t, 1, dummyListenerCall)
}

func TestStartAndSetOperation(t *testing.T) {
	t.Parallel()

	var (
		httpRequestListenerCall int
	)

	rootOp := operation.NewRootOperation()
	httpRequestListener := func(c *int) operation.EventListener[*httpRequestOperation, httpRequestOperationArg] {
		return func(op *httpRequestOperation, arg httpRequestOperationArg) {
			*c++
		}
	}(&httpRequestListenerCall)
	operation.OnStart(rootOp, httpRequestListener)
	operation.InitRootOperation(rootOp)

	dummyOp := &dummyOperation{
		Operation: operation.NewOperation(nil),
	}

	ctx := operation.StartAndSetOperation(context.Background(), dummyOp, dummyOperationArg{})
	foundOp, found := operation.FindOperation[dummyOperation](ctx)
	assert.True(t, found)
	assert.Equal(t, dummyOp, foundOp)
	assert.Equal(t, 0, httpRequestListenerCall)

	httpOp := &httpRequestOperation{
		Operation: operation.NewOperation(dummyOp),
	}

	ctx = operation.StartAndSetOperation(ctx, httpOp, httpRequestOperationArg{})
	foundHttpOp, found := operation.FindOperation[httpRequestOperation](ctx)
	assert.True(t, found)
	assert.Equal(t, httpOp, foundHttpOp)
	assert.Equal(t, 1, httpRequestListenerCall) // assert that the listener is called via StartOperation()

	foundOp, found = operation.FindOperation[dummyOperation](ctx)
	assert.True(t, found)
	assert.Equal(t, dummyOp, foundOp)
}

func TestFinishOperation(t *testing.T) {
	t.Parallel()

	var (
		httpRequestListenerCall int
		dummyListenerCall       int
	)

	httpRequestListener := func(c *int) operation.EventListener[*httpRequestOperation, httpRequestOperationResult] {
		return func(op *httpRequestOperation, arg httpRequestOperationResult) {
			*c++
		}
	}(&httpRequestListenerCall)

	dummyListener := func(c *int) operation.EventListener[*dummyOperation, dummyOperationResult] {
		return func(op *dummyOperation, arg dummyOperationResult) {
			*c++
		}
	}(&dummyListenerCall)

	rootOp := operation.NewRootOperation()
	operation.OnFinish(rootOp, httpRequestListener)
	operation.OnFinish(rootOp, dummyListener)
	operation.InitRootOperation(rootOp)

	httpOp := &httpRequestOperation{
		Operation: operation.NewOperation(nil),
	}

	assert.Equal(t, 0, httpRequestListenerCall)
	assert.Equal(t, 0, dummyListenerCall)

	operation.FinishOperation(httpOp, httpRequestOperationResult{})

	assert.Equal(t, 1, httpRequestListenerCall)
	assert.Equal(t, 0, dummyListenerCall)

	dummyOp := &dummyOperation{
		Operation: operation.NewOperation(httpOp),
	}

	operation.FinishOperation(dummyOp, dummyOperationResult{})
	assert.Equal(t, 1, httpRequestListenerCall)
	assert.Equal(t, 1, dummyListenerCall)
}

type httpRequestOperation struct {
	operation.Operation
}

type httpRequestOperationArg struct{}
type httpRequestOperationResult struct{}

func (httpRequestOperationArg) IsArgOf(*httpRequestOperation)       {}
func (httpRequestOperationResult) IsResultOf(*httpRequestOperation) {}

type dummyOperation struct {
	operation.Operation
}

type dummyOperationArg struct{}
type dummyOperationResult struct{}

func (dummyOperationArg) IsArgOf(*dummyOperation)       {}
func (dummyOperationResult) IsResultOf(*dummyOperation) {}

func StartAndSetDummyOperation(ctx context.Context) (*dummyOperation, context.Context) {
	parent, _ := operation.FindOperationFromContext(ctx)
	op := &dummyOperation{
		Operation: operation.NewOperation(parent),
	}

	return op, operation.StartAndSetOperation(ctx, op, dummyOperationArg{})
}
