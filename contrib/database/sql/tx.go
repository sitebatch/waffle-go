package sql

import "database/sql/driver"

type waffleTx struct {
	driver.Tx
}

func (t waffleTx) Commit() error {
	return t.Tx.Commit()
}

func (t waffleTx) Rollback() error {
	return t.Tx.Rollback()
}
