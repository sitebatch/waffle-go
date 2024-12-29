package log

import (
	"fmt"
	"log/slog"
	"os"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	level         = LevelWarn
	logger Logger = NewLogger()
)

type Logger interface {
	Log(level Level, msg string, args ...any)
}

type DefaultLogger struct {
	l *slog.Logger
}

func NewLogger() Logger {
	return &DefaultLogger{
		l: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func (l *DefaultLogger) Log(level Level, msg string, args ...any) {
	switch level {
	case LevelDebug:
		l.l.Debug(msg, args...)
	case LevelInfo:
		l.l.Info(msg, args...)
	case LevelWarn:
		l.l.Warn(msg, args...)
	case LevelError:
		l.l.Error(msg, args...)
	}
}

func SetLevel(l Level) {
	level = l
}

func GetLevel() Level {
	return level
}

func DebugEnabled() bool {
	return level == LevelDebug
}

func Debug(msg string, args ...interface{}) {
	if DebugEnabled() {
		log(LevelDebug, msg, args...)
	}
}

func Info(msg string, args ...interface{}) {
	log(LevelInfo, msg, args...)
}

func Warn(msg string, args ...interface{}) {
	log(LevelWarn, msg, args...)
}

func Error(msg string, args ...interface{}) {
	log(LevelError, msg, args...)
}

func log(level Level, msg string, args ...interface{}) {
	logger.Log(level, fmt.Sprintf("[waffle] %s", msg), args...)
}
