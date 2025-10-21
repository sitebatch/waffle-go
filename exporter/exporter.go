package exporter

import (
	"context"
	"sync/atomic"

	"github.com/sitebatch/waffle-go/waf"
)

var (
	globalExporter = defaultExporterValue()
)

type eventExporterProvider struct {
	ep EventExporter
}

type EventExporter interface {
	Export(ctx context.Context, event waf.ReadOnlyDetectionEvents) error
}

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
