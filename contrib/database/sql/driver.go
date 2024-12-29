package sql

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
)

type waffleDriver struct {
	driver.Driver
}

var (
	// For type assertion
	_ driver.Driver = &waffleDriver{}

	regMu sync.Mutex
)

func Register(driverName string) (string, error) {
	db, err := sql.Open(driverName, "")
	if err != nil {
		return "", err
	}

	driver := db.Driver()
	if err = db.Close(); err != nil {
		return "", err
	}

	regMu.Lock()
	defer regMu.Unlock()
	name := fmt.Sprintf("%s-waffle-%d", driverName, len(sql.Drivers()))
	sql.Register(name, Wrap(driver))

	return name, nil
}

func (d waffleDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}

	return waffleConn{c}, nil
}

func Wrap(d driver.Driver) driver.Driver {
	return waffleDriver{d}
}
