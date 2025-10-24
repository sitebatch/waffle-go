package handler_test

import (
	"testing"

	"github.com/sitebatch/waffle-go/handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetErrorHandler(t *testing.T) {
	t.Parallel()

	h := handler.GetErrorHandler()
	_, ok := h.(*handler.LogErrorHandler)
	assert.True(t, ok)

	assert.NotPanics(t, func() {
		h.HandleError(assert.AnError)
	})
}

func TestSetErrorHandler(t *testing.T) {
	t.Parallel()

	testHandler := &testErrorHandler{}
	handler.SetErrorHandler(testHandler)
	h := handler.GetErrorHandler()
	_, ok := h.(*testErrorHandler)
	assert.True(t, ok)

	require.Equal(t, 0, testHandler.calls)
	assert.NotPanics(t, func() {
		h.HandleError(assert.AnError)
	})
	assert.Equal(t, 1, testHandler.calls)

	doNotSetHandler := &testErrorHandler{}
	handler.SetErrorHandler(doNotSetHandler)
	h = handler.GetErrorHandler()
	h.HandleError(assert.AnError)
	assert.Equal(t, 0, doNotSetHandler.calls)
	assert.Equal(t, 2, testHandler.calls)
}

type testErrorHandler struct {
	calls int
}

func (h *testErrorHandler) HandleError(err error) {
	h.calls++
}
