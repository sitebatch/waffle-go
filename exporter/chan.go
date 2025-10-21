package exporter

import (
	"context"

	"github.com/sitebatch/waffle-go/waf"
)

var _ EventExporter = (*ChanExporter)(nil)

type ChanExporter struct {
	wCh chan waf.ReadOnlyDetectionEvents
}

func NewChanExporter(ch chan waf.ReadOnlyDetectionEvents) *ChanExporter {
	return &ChanExporter{
		wCh: ch,
	}
}

func (e *ChanExporter) Export(_ context.Context, event waf.ReadOnlyDetectionEvents) error {
	e.wCh <- event
	return nil
}
