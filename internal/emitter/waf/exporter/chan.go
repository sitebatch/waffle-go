package exporter

import (
	"context"

	"github.com/sitebatch/waffle-go/internal/emitter/waf"
)

var (
	ExporterNameChan waf.ExporterName = "chan"
)

type ChanExporter struct {
	Ch chan waf.ReadOnlyDetectionEvents
}

func NewChanExporter(ch chan waf.ReadOnlyDetectionEvents) *ChanExporter {
	return &ChanExporter{
		Ch: ch,
	}
}

func (e *ChanExporter) Export(_ context.Context, event waf.ReadOnlyDetectionEvents) error {
	e.Ch <- event
	return nil
}
