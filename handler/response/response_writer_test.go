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
	assert.Equal(t, 200, testWriter.Code)
	assert.True(t, waffleWriter.HeaderWritten())

	writer.WriteHeader(400)
	assert.Equal(t, 200, testWriter.Code)
}

func TestResponseWriter_Write(t *testing.T) {
	response.InitResponseWriterFeature()

	testWriter := httptest.NewRecorder()
	writer, waffleWriter := response.NewWaffleResponseWriter(testWriter)
	writer.Write([]byte("Hello, World!"))
	assert.Equal(t, "Hello, World!", testWriter.Body.String())
	assert.True(t, waffleWriter.BodyWritten())

	writer.Write([]byte("Goodbye, World!"))
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
