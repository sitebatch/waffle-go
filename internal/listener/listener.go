package listener

import "github.com/sitebatch/waffle-go/internal/operation"

type Listener interface {
	Name() string
}

type NewListener func(operation.Operation) (Listener, error)
