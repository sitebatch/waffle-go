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

// EventExporter exports WAF detection events to any desired location.
type EventExporter interface {
	// Export transforms and transmits event data to any desired location.
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
