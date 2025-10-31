# gorm

This package provides integration instructions for using [GORM](https://gorm.io/) with Waffle protection. While GORM itself doesn't require wrapping, you can apply Waffle's SQL injection protection by using the Waffle database driver.

## Installation

```bash
go get github.com/sitebatch/waffle-go/contrib/gorm.io/gorm
```

## Usage

To apply Waffle protection to GORM applications, use the Waffle database driver with GORM:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/sitebatch/waffle-go"
	waffleSql "github.com/sitebatch/waffle-go/contrib/database/sql"
	"github.com/sitebatch/waffle-go/waf"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Product struct {
	gorm.Model
	Code string
	Name string
}

func main() {
	// Register Waffle driver
	driverName, err := waffleSql.Register(sqlite.DriverName)
	if err != nil {
		log.Fatal(err)
	}

	// Open database connection using Waffle's driver
	sqlDB, err := waffleSql.Open(driverName, "file:test.db?cache=shared&mode=memory")
	if err != nil {
		log.Fatal(err)
	}

	db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: sqlDB}), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&Product{})

	// Start Waffle
	if err := waffle.Start(); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	var product Product

	// Execute queries - Waffle will prevent SQL injection
	maliciousCode := "D42') OR 1=1--"
	query := fmt.Sprintf("code = '%s'", maliciousCode)
	result := db.WithContext(ctx).Where(query).First(&product)

	if result.Error != nil {
		if waf.IsSecurityBlockingError(result.Error) {
			// Handle blocked query
			log.Printf("Blocked SQL injection attempt: %v", result.Error)
		}
	}
}
```
