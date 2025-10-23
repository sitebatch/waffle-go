package response_test

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sitebatch/waffle-go/handler/response"
	"github.com/stretchr/testify/assert"
)

func TestWaffleResponseWriter_Unwrap(t *testing.T) {
	response.InitResponseWriterFeature()

	testWriter := httptest.NewRecorder()
	_, waffleWriter := response.NewWaffleResponseWriter(testWriter)
	assert.Same(t, testWriter, waffleWriter.Unwrap())
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	response.InitResponseWriterFeature()

	testWriter := httptest.NewRecorder()
	writer, waffleWriter := response.NewWaffleResponseWriter(testWriter)

	writer.WriteHeader(200)
	waffleWriter.WriteHeader(200)

	assert.Equal(t, 200, testWriter.Code)
	assert.Equal(t, 200, waffleWriter.Status())

	writer.WriteHeader(400)
	waffleWriter.WriteHeader(400)
	assert.Equal(t, 200, testWriter.Code)
	assert.Equal(t, 200, waffleWriter.Status())

	waffleWriter.Reset()
	waffleWriter.WriteHeader(400)
	assert.Equal(t, 400, waffleWriter.Status())
}

func TestResponseWriter_Write(t *testing.T) {
	response.InitResponseWriterFeature()

	testWriter := httptest.NewRecorder()
	writer, waffleWriter := response.NewWaffleResponseWriter(testWriter)

	_, _ = writer.Write([]byte("Hello, World!"))
	assert.Equal(t, "", testWriter.Body.String())
	assert.NoError(t, waffleWriter.Commit())
	assert.Equal(t, "Hello, World!", testWriter.Body.String())

	_, _ = writer.Write([]byte("Goodbye, World!"))
	assert.NoError(t, waffleWriter.Commit())
	assert.Equal(t, "Hello, World!Goodbye, World!", testWriter.Body.String())
}

func TestResponseWriter_Hijack(t *testing.T) {
	response.InitResponseWriterFeature()

	testWriter := httptest.NewRecorder()
	writer, _ := response.NewWaffleResponseWriter(testWriter)
	assert.Panics(t, func() {
		writer.(http.Hijacker).Hijack()
	})

	hijacker := &mockHijackerResponseWriter{ResponseWriter: testWriter}
	writer, _ = response.NewWaffleResponseWriter(hijacker)

	conn, _, err := writer.(http.Hijacker).Hijack()
	assert.Nil(t, conn)
	assert.Nil(t, err)
}

type mockHijackerResponseWriter struct {
	http.ResponseWriter
}

func (m *mockHijackerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}
