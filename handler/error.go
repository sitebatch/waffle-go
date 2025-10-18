package handler

import (
	"log"
	"sync"
	"sync/atomic"
)

var (
	globalErrorHandlerHolder = defaultErrorHandlerHolder()
	delegateErrorHandlerOnce sync.Once
)

// ErrorHandler is an interface for handling operation errors.
type ErrorHandler interface {
	// HandleError handles any error occurred during operation processing.
	HandleError(err error)
}

func GetErrorHandler() ErrorHandler {
	return globalErrorHandlerHolder.Load().(errorHandlerHolder).handler
}

func SetErrorHandler(handler ErrorHandler) {
	delegateErrorHandlerOnce.Do(func() {
		globalErrorHandlerHolder.Store(
			errorHandlerHolder{handler: handler},
		)
	})
}

type (
	errorHandlerHolder struct {
		handler ErrorHandler
	}

	LogErrorHandler struct{}
)

var _ ErrorHandler = (*LogErrorHandler)(nil)

func (d *LogErrorHandler) HandleError(err error) {
	log.Print(err)
}

func defaultErrorHandlerHolder() *atomic.Value {
	v := &atomic.Value{}
	v.Store(errorHandlerHolder{handler: &LogErrorHandler{}})

	return v
}
