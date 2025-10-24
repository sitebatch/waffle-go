package log

import (
	"log"
	"os"
	"sync/atomic"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
)

var globalLogger = func() *atomic.Pointer[logr.Logger] {
	l := stdr.New(log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile))

	p := new(atomic.Pointer[logr.Logger])
	p.Store(&l)
	return p
}()

func GetLogger() logr.Logger {
	return *globalLogger.Load()
}

func SetLogger(logger logr.Logger) {
	globalLogger.Store(&logger)
}

func Debug(format string, v ...any) {
	GetLogger().V(8).Info(format, v...)
}

func Info(format string, v ...any) {
	GetLogger().V(4).Info(format, v...)
}

func Warn(format string, v ...any) {
	GetLogger().V(1).Info(format, v...)
}

func Error(err error, msg string, keysAndValues ...any) {
	GetLogger().Error(err, msg, keysAndValues...)
}
