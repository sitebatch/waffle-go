# gorm

This package provides a wrapper for GORM protected by Waffle. However, it currently does not provide any functions as there is no need to wrap GORM.

# Usage

To apply Waffle protection to GORM, do the following:

```go
import (
	waffleSql "github.com/sitebatch/waffle-go/contrib/database/sql"
	"gorm.io/driver/sqlite"
)

_, err := waffleSql.Register(sqlite.DriverName)
sqlDB, err := waffleSql.Open(sqlite.DriverName, dsn)
```
