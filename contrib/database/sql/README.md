# database/sql

This package provides a wrapper for [`database/sql`](https://pkg.go.dev/database/sql) protected by Waffle. By replacing it with a drop-in, you can prevent SQL injection if you are using `database/sql`.

# Usage

to english: When executing a statement, use the Waffle database driver instead of `database/sql`. At this time, you need to pass the Waffle's operation `context`.

```go
import (
   	waffleSQL "github.com/sitebatch/waffle-go/contrib/database/sql"

	_ "github.com/mattn/go-sqlite3" // or any other database driver
)

db, err := waffleSQL.Open("<driver>", "<dataSourceName>")
_, err := database.QueryContext(ctx, "<query>")
```

# Example

See [example/sql](../../../example/sql/).
