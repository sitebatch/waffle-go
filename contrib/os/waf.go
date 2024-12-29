package os

import (
	"context"
	"os"

	osHandler "github.com/sitebatch/waffle-go/internal/emitter/os"
)

// ProtectReadFile protects file reading from attacks such as directory traversal and executes os.ReadFile.
func ProtectReadFile(ctx context.Context, name string) ([]byte, error) {
	if err := osHandler.ProtectFileOperation(ctx, name); err != nil {
		return nil, err
	}

	return os.ReadFile(name)
}

// ProtectOpenFile protects file opening from attacks such as directory traversal and executes os.OpenFile.
func ProtectOpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (*os.File, error) {
	if err := osHandler.ProtectFileOperation(ctx, name); err != nil {
		return nil, err
	}

	return os.OpenFile(name, flag, perm)
}
