package log_test

import (
	"bytes"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	log.SetLogger(newBufLogger(&buf, 4))
	log.Info("info")

	assert.Equal(t, `"level"=4 "msg"="info"`, buf.String())
}

func TestDebug(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	log.SetLogger(newBufLogger(&buf, 8))
	log.Debug("debug")

	assert.Equal(t, `"level"=8 "msg"="debug"`, buf.String())
}

func TestWarn(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	log.SetLogger(newBufLogger(&buf, 1))
	log.Warn("warn")

	assert.Equal(t, `"level"=1 "msg"="warn"`, buf.String())
}

func TestError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	log.SetLogger(newBufLogger(&buf, 0))
	log.Error(assert.AnError, "error occurred", "key1", "value1")

	assert.Equal(t, `"msg"="error occurred" "error"="`+assert.AnError.Error()+`" "key1"="value1"`, buf.String())
}

func newBufLogger(buf *bytes.Buffer, verbosity int) logr.Logger {
	return funcr.New(func(_, args string) {
		_, _ = buf.WriteString(args)
	}, funcr.Options{
		Verbosity: verbosity,
	})
}
