package waf

import (
	"context"
	"sync/atomic"
)

var (
	globalExporter = defaultExporterValue()
)

type (
	ExporterName string
	ExportConfig struct{}

	EventExporter interface {
		Export(ctx context.Context, event ReadOnlyDetectionEvents) error
	}

	eventExporterProvider struct {
		ep EventExporter
	}
)

func GetExporter() EventExporter {
	v := globalExporter.Load().(*eventExporterProvider)
	return v.ep
}

func SetExporter(exporter EventExporter) {
	globalExporter.Store(&eventExporterProvider{
		ep: exporter,
	})
}

func defaultExporterValue() *atomic.Value {
	v := &atomic.Value{}
	v.Store(&eventExporterProvider{
		ep: newNopExporter(),
	})
	return v
}

type nopExporter struct{}

func newNopExporter() *nopExporter {
	return &nopExporter{}
}

func (e *nopExporter) Export(ctx context.Context, event ReadOnlyDetectionEvents) error {
	return nil
}
