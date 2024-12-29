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
