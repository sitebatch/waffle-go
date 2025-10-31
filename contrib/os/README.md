# os

This package provides a wrapper around the Go standard library's [`os`](https://pkg.go.dev/os) package, enhanced with Waffle's security features.  
It includes functions that wrap `os.ReadFile` and `os.OpenFile`, featuring protection mechanisms to prevent unauthorized access to sensitive files through directory traversal attacks, LFI, and other vulnerabilities.

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/os
```

## Usage

Replaces standard `os` module file operations with functions provided by this package:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/sitebatch/waffle-go"
	waffleOs "github.com/sitebatch/waffle-go/contrib/os"
	"github.com/sitebatch/waffle-go/waf"
)

func main() {
	// Start Waffle
	if err := waffle.Start(); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Protected file reading - prevents sensitive file access
	filename := "../../../../env"
	data, err := waffleOs.ProtectReadFile(ctx, filename)
	if err != nil {
		if waf.IsSecurityBlockingError(err) {
			fmt.Printf("file read blocked by Waffle: %v\n", err)
			return
		}
		return
	}

	log.Printf("File content: %s", data)
}
```
