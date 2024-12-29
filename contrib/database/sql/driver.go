package sql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
)

type waffleDriver struct {
	driver.Driver
}

type waffleConnector struct {
	driver.Connector
	driver *waffleDriver
}

type dsnConnector struct {
	dsn    string
	driver driver.Driver
}

var (
	// For type assertion
	_ driver.Driver        = &waffleDriver{}
	_ driver.DriverContext = &waffleDriver{}
	_ driver.Connector     = &waffleConnector{}

	regMu sync.Mutex
)

func Wrap(d driver.Driver) driver.Driver {
	return waffleDriver{d}
}

func Open(driverName, dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open(driverName, "")
	if err != nil {
		return nil, err
	}

	d := db.Driver()
	if err = db.Close(); err != nil {
		return nil, err
	}

	waffleDriver := waffleDriver{d}
	if _, ok := d.(driver.DriverContext); ok {
		connector, err := waffleDriver.OpenConnector(dataSourceName)
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(connector), nil
	}

	return sql.OpenDB(dsnConnector{dsn: dataSourceName, driver: waffleDriver}), nil
}

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

func (d *waffleDriver) OpenConnector(name string) (driver.Connector, error) {
	c, err := d.Driver.(driver.DriverContext).OpenConnector(name)
	if err != nil {
		return nil, err
	}

	return &waffleConnector{Connector: c, driver: d}, nil
}

func (c *waffleConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return waffleConn{conn}, nil
}

func (c *waffleConnector) Driver() driver.Driver {
	return c.driver
}

func (t dsnConnector) Connect(_ context.Context) (driver.Conn, error) {
	return t.driver.Open(t.dsn)
}

func (t dsnConnector) Driver() driver.Driver {
	return t.driver
}
