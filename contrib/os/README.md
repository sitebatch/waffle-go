# os

This package provides a wrapper for [`os`](https://pkg.go.dev/os) protected by Waffle.  
It provides functions that wrap `os.ReadFile` and `os.WriteFile` to prevent directory traversal and access to sensitive files.

# Usage

When accessing a file, use the Waffle's file functions instead of `os`.

```go
import (
    waffleOs "github.com/sitebatch/waffle-go/contrib/os"
)

// ProtectReadFile wraps os.ReadFile
data, err := waffleOs.ProtectReadFile(ctx, "<filename>")

// ProtectOpenFile wraps os.OpenFile
f, err := waffleOs.ProtectOpenFile("notes.txt", os.O_RDWR|os.O_CREATE, 0644)
```
