package sql

import (
	"context"
	"database/sql/driver"

	sqliHandler "github.com/sitebatch/waffle-go/internal/emitter/sql"
)

// For type assertion
var _ driver.Conn = (*waffleConn)(nil)

type waffleConn struct {
	driver.Conn
}

func (c waffleConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if connBeginTx, ok := c.Conn.(driver.ConnBeginTx); ok {
		tx, err := connBeginTx.BeginTx(ctx, opts)
		if err != nil {
			return nil, err
		}

		return waffleTx{tx}, nil
	}

	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}

	return waffleTx{tx}, nil
}

func (c waffleConn) Ping(ctx context.Context) (err error) {
	if pinger, ok := c.Conn.(driver.Pinger); ok {
		err = pinger.Ping(ctx)
	}
	return
}

func (c waffleConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (rows driver.Rows, err error) {
	if queryerContext, ok := c.Conn.(driver.QueryerContext); ok {
		if err := sqliHandler.ProtectSQLOperation(ctx, query); err != nil {
			return nil, err
		}
		rows, err = queryerContext.QueryContext(ctx, query, args)
		return rows, err
	}

	if queryer, ok := c.Conn.(driver.Queryer); ok {
		dargs, err := namedValueToValue(args)
		if err != nil {
			return nil, err
		}

		if err := sqliHandler.ProtectSQLOperation(ctx, query); err != nil {
			return nil, err
		}

		rows, err = queryer.Query(query, dargs)
		return rows, err
	}

	return nil, driver.ErrSkip
}

func (c waffleConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (result driver.Result, err error) {
	if execContext, ok := c.Conn.(driver.ExecerContext); ok {
		if err := sqliHandler.ProtectSQLOperation(ctx, query); err != nil {
			return nil, err
		}

		result, err = execContext.ExecContext(ctx, query, args)
		return result, err
	}

	if execer, ok := c.Conn.(driver.Execer); ok {
		dargs, err := namedValueToValue(args)
		if err != nil {
			return nil, err
		}

		if err := sqliHandler.ProtectSQLOperation(ctx, query); err != nil {
			return nil, err
		}

		result, err = execer.Exec(query, dargs)
		return result, err
	}

	return nil, driver.ErrSkip
}

func (c waffleConn) PrepareContext(ctx context.Context, query string) (stmt driver.Stmt, err error) {
	if preparerCtx, ok := c.Conn.(driver.ConnPrepareContext); ok {
		stmt, err = preparerCtx.PrepareContext(ctx, query)
		if err != nil {
			return nil, err
		}

		return &waffleStmt{Stmt: stmt, query: query}, nil
	}

	stmt, err = c.Prepare(query)
	if err != nil {
		return nil, err
	}

	return &waffleStmt{Stmt: stmt, query: query}, nil
}
