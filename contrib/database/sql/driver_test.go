package sql_test

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	waffleSql "github.com/sitebatch/waffle-go/contrib/database/sql"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	t.Parallel()

	driverName, err := waffleSql.Register("sqlite3")
	assert.NoError(t, err)

	_, err = sql.Open(driverName, "file:test.db?cache=shared&mode=memory")
	assert.NoError(t, err)
}
