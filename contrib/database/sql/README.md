# database/sql

This package provides a wrapper for [`database/sql`](https://pkg.go.dev/database/sql) protected by Waffle. By using this drop-in replacement, you can prevent SQL injection attacks when using `database/sql`.

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/database/sql
```

## Usage

Replace your standard `database/sql` imports with the this package.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/sitebatch/waffle-go"
	waffleSQL "github.com/sitebatch/waffle-go/contrib/database/sql"
	"github.com/sitebatch/waffle-go/waf"

	_ "github.com/mattn/go-sqlite3" // or any other database driver
)

func main() {
	// Start Waffle
	if err := waffle.Start(); err != nil {
		log.Fatal(err)
	}

	// Open database connection using Waffle wrapper
	db, err := waffleSQL.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		log.Fatal(err)
	}

	// Create a sample table
	if _, err := db.Exec("CREATE TABLE users(id int, email text, password text);"); err != nil {
		panic(err)
	}
	defer db.Close()

	ctx := context.Background()

	// Execute queries - Waffle will prevent SQL injection
	userID := "1' OR '1'='1"
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		if waf.IsSecurityBlockingError(err) {
			// Handle blocked query
			log.Printf("Blocked SQL injection attempt: %v", err)
			return
		}

		log.Fatal(err)
		return
	}
	defer rows.Close()
}
```
