package operation

/*
	Package operation provides a way to manage the operation of the application.
	An operation is a unit of application process (e.g. HTTP Request handling, Execute SQL Query, etc...) that can be started and finished.
	When an operation is started or finished, events are notified to event listeners.

	This implementation is inspired by Dyngo in dd-trace-go.
	I'm implementing only the necessary functions in waffle with reference to dd-trace-go.
	ref. https://github.com/DataDog/dd-trace-go/tree/d39332478672b57617dafc315fc258e888067143/internal/appsec/dyngo
*/

import (
	"context"
	"sync"
)

// rootOperation is the root operation of the application.
// This operation has all event handlers registered and events are notified.
var rootOperation Operation

var rootOperationInitialized bool

// Operation is the interface that wraps the basic operation methods.
// An operation is a unit of application process (e.g. HTTP Request handling, Execute SQL Query, etc...) that can be started and finished.
// When an operation is started or finished, events are notified to event listeners.
type Operation interface {
	// GetRootID returns the root operation ID.
	GetRootID() string
	// GetID returns the operation ID.
	GetID() string
	// Parent returns the parent operation.
	Parent() Operation
	// unwrap returns the operation itself.
	unwrap() *operation
}

type operationContextKey struct{}

type listenerID[T any] struct{}

// EventListener is a function type that is called when an event is emitted.
// At the start and end of the Operation, you can execute func(O, T)
type EventListener[O Operation, T any] func(O, T)

// eventListener is a struct that holds event listeners.
type eventListenerManager struct {
	// listeners is a map of event listeners.
	listeners map[any][]any

	mu sync.RWMutex
}

type operation struct {
	// id is the operation ID.
	id string
	// parent is the parent operation.
	parent Operation
	// eventListener is the event listener of the operation.
	eventListenerManager

	mu sync.RWMutex
}

// IsArgOf is a marker interface that marks the type as an argument of the operation.
type ArgOf[O Operation] interface {
	IsArgOf(O)
}

// IsResultOf is a marker interface that marks the type as a result of the operation.
type ResultOf[O Operation] interface {
	IsResultOf(O)
}

// NewRootOperation creates a new root operation.
func NewRootOperation() Operation {
	return &operation{id: generateID(), parent: nil}
}

// InitRootOperation initializes the root operation.
// The root operation should be passed to op created by NewRootOperation.
func InitRootOperation(op Operation) {
	rootOperation = op
	rootOperationInitialized = true
}

func IsRootOperationInitialized() bool {
	return rootOperationInitialized
}

// NewOperation creates a new operation.
func NewOperation(parent Operation) Operation {
	if parent == nil {
		parent = rootOperation
	}

	return &operation{id: generateID(), parent: parent}
}

func (o *operation) GetID() string {
	return o.id
}

func (o *operation) GetRootID() string {
	for current := o.unwrap().parent; current != nil; current = current.unwrap().parent {
		return current.GetID()
	}

	return o.id
}

// Parent returns the parent operation.
func (o *operation) Parent() Operation {
	return o.parent
}

// unwrap returns the operation itself.
func (o *operation) unwrap() *operation { return o }

// FindOperationFromContext returns the operation from the context.
// This is used to share operations between application processes such as executing SQL queries and sending HTTP requests.
func FindOperationFromContext(ctx context.Context) (Operation, bool) {
	if ctx == nil {
		return nil, false
	}

	op, ok := ctx.Value(operationContextKey{}).(Operation)
	return op, ok
}

// FindOperation returns the Operation of T if the context has the Operation of T.
// This is used to identify the relationship between application processes.
func FindOperation[T any, O interface {
	Operation
	*T
}](ctx context.Context) (*T, bool) {
	op, found := FindOperationFromContext(ctx)
	if !found {
		return nil, false
	}

	for current := op; current != nil; current = current.unwrap().parent {
		if o, ok := current.(O); ok {
			return o, true
		}
	}

	return nil, false
}

// StartOperation starts the operation.
// This function notifies the event listeners of the parent operation.
func StartOperation[O Operation, E ArgOf[O]](op O, args E) {
	for current := op.unwrap().parent; current != nil; current = current.unwrap().parent {
		emitEvent(&current.unwrap().eventListenerManager, op, args)
	}
}

// StartAndRegisterOperation starts the operation and registers the operation to the context.
func StartAndRegisterOperation[O Operation, E ArgOf[O]](ctx context.Context, op O, args E) context.Context {
	StartOperation(op, args)
	return RegisterOperation(ctx, op)
}

// RegisterOperation registers the operation to the context.
func RegisterOperation(ctx context.Context, op Operation) context.Context {
	return context.WithValue(ctx, operationContextKey{}, op)
}

// FinishOperation finishes the operation.
// This function notifies the event listeners of the operation and the parent operation.
func FinishOperation[O Operation, E ResultOf[O]](op O, results E) {
	o := op.unwrap()

	o.mu.RLock()
	defer o.mu.RUnlock()

	var current Operation = op
	for ; current != nil; current = current.unwrap().parent {
		emitEvent(&current.unwrap().eventListenerManager, op, results)
	}
}

// On registers the event listener to the operation.
func OnStart[O Operation, E ArgOf[O]](op Operation, l EventListener[O, E]) {
	o := op.unwrap()
	o.mu.RLock()
	defer o.mu.RUnlock()

	addEventListener(&o.eventListenerManager, l)
}

// OnFinish registers the event listener to the operation.
func OnFinish[O Operation, E ResultOf[O]](op Operation, l EventListener[O, E]) {
	o := op.unwrap()
	o.mu.RLock()
	defer o.mu.RUnlock()

	addEventListener(&o.eventListenerManager, l)
}

func addEventListener[O Operation, T any](r *eventListenerManager, l EventListener[O, T]) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.listeners == nil {
		r.listeners = map[any][]any{}
	}

	key := listenerID[EventListener[O, T]]{}
	r.listeners[key] = append(r.listeners[key], l)
}

func emitEvent[O Operation, T any](r *eventListenerManager, op O, v T) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.listeners == nil {
		return
	}

	for _, listener := range r.listeners[listenerID[EventListener[O, T]]{}] {
		listener.(EventListener[O, T])(op, v)
	}
}
