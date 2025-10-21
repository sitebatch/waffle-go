package exporter

import (
	"context"

	"github.com/sitebatch/waffle-go/waf"
)

var _ EventExporter = (*nopExporter)(nil)

type nopExporter struct{}

func newNopExporter() *nopExporter {
	return &nopExporter{}
}

func (e *nopExporter) Export(_ context.Context, _ waf.ReadOnlyDetectionEvents) error {
	return nil
}
