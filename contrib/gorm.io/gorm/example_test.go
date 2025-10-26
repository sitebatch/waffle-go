package gorm_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sitebatch/waffle-go"
	waffleSql "github.com/sitebatch/waffle-go/contrib/database/sql"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Test(t *testing.T) {
	t.Parallel()

	type Product struct {
		gorm.Model
		Code  string
		Price uint
	}

	_, err := waffleSql.Register(sqlite.DriverName)
	require.NoError(t, err)

	sqlDB, err := waffleSql.Open(sqlite.DriverName, fmt.Sprintf("file:test-%d.db?cache=shared&mode=memory", time.Now().UnixNano()))
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: sqlDB}), &gorm.Config{})
	require.NoError(t, err)

	db.AutoMigrate(&Product{})
	db.Create(&Product{Code: "D42", Price: 100})

	waffle.Start()
	ctx := context.Background()
	_, ctx = http.StartHTTPRequestHandlerOperation(ctx, http.HTTPRequestHandlerOperationArg{})

	var product Product

	tx := db.WithContext(ctx)
	tx.First(&product, 1)
	assert.Equal(t, "D42", product.Code)

	tx.First(&product, "code = ?", "D42")
	assert.Equal(t, uint(100), product.Price)

	var product2 Product
	result := tx.Where(fmt.Sprintf("code = '%s'", "D42') OR 1=1--")).First(&product2)
	assert.Error(t, result.Error)
	var secErr *waf.SecurityBlockingError
	assert.ErrorAs(t, result.Error, &secErr)
}
