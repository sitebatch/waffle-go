package sql_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/sitebatch/waffle-go"
	waffleSql "github.com/sitebatch/waffle-go/contrib/database/sql"
	"github.com/sitebatch/waffle-go/internal/emitter/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryContext(t *testing.T) {
	t.Parallel()

	db := createDatabase(t)
	defer db.Close()

	waffle.Start()

	ctx := context.Background()
	_, ctx = http.StartHTTPRequestHandlerOperation(ctx, http.HTTPRequestHandlerOperationArg{})

	rows, err := db.QueryContext(ctx, "SELECT 1 WHERE 1 = ?", 1)
	assert.NoError(t, err)

	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			assert.NoError(t, err)
		}
	}

	if err := rows.Err(); err != nil {
		assert.NoError(t, err)
	}

	t.Run("when SQLi is detected", func(t *testing.T) {
		_, err := db.QueryContext(ctx, "SELECT 1 WHERE 1 = '1 OR 1 = 1'")
		assert.Error(t, err)
	})
}

func TestExecContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type arrange struct {
		stmts []string
	}

	testCases := map[string]struct {
		arrange arrange
		stmt    string
		n       int64
	}{
		"when rows are affected": {
			arrange: arrange{
				stmts: []string{
					`DROP TABLE IF EXISTS foo;`,
					`CREATE TABLE foo (id INTEGER NOT NULL PRIMARY KEY, name text);`,
				},
			},
			stmt: "INSERT INTO foo (id, name) VALUES (1, 'foo');",
			n:    1,
		},
	}

	for name, tt := range testCases {
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			db := createDatabase(t)
			defer db.Close()

			for _, stmt := range tt.arrange.stmts {
				_, err := db.ExecContext(ctx, stmt)
				require.NoError(t, err)
			}

			res, err := db.ExecContext(ctx, tt.stmt)
			assert.NoError(t, err)

			n, err := res.RowsAffected()
			assert.NoError(t, err)
			assert.Equal(t, tt.n, n)
		})
	}
}

func TestBeginTx(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	db := createDatabase(t)
	defer db.Close()

	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS foo;")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "CREATE TABLE foo (id INTEGER NOT NULL PRIMARY KEY, name text);")
	require.NoError(t, err)

	t.Run("when transaction is committed", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		assert.NoError(t, err)

		stmt, err := tx.Prepare("INSERT INTO foo (id, name) VALUES (?, ?)")
		assert.NoError(t, err)
		defer stmt.Close()

		_, err = stmt.Exec(1, "Hello, World!")
		assert.NoError(t, err)

		assert.NoError(t, tx.Commit())

		res, err := db.ExecContext(ctx, "SELECT * FROM foo")
		assert.NoError(t, err)

		n, err := res.RowsAffected()
		assert.NoError(t, err)
		assert.Equal(t, int64(1), n)
	})

	t.Run("when transaction is rolled back", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)

		stmt, err := tx.Prepare("INSERT INTO foo (id, name) VALUES (?, ?)")
		require.NoError(t, err)
		defer stmt.Close()

		_, err = stmt.Exec(2, "Rollback")
		require.NoError(t, err)

		assert.NoError(t, tx.Rollback())

		rows, err := db.QueryContext(ctx, "SELECT * FROM foo WHERE id = 2")
		require.NoError(t, err)

		assert.Equal(t, false, rows.Next())
	})
}

func createDatabase(t *testing.T) *sql.DB {
	t.Helper()
	driverName, err := waffleSql.Register("sqlite3")
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open(driverName, fmt.Sprintf("file:test-%d.db?cache=shared&mode=memory", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}

	return db
}
