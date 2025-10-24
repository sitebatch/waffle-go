package exporter

import (
	"context"
	"errors"

	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/waf"
)

var _ EventExporter = (*StdoutExporter)(nil)

type StdoutExporter struct{}

func NewStdoutExporter() *StdoutExporter {
	return &StdoutExporter{}
}

func (e *StdoutExporter) Export(ctx context.Context, event waf.ReadOnlyDetectionEvents) error {
	for _, evt := range event.Events() {
		err := errors.New(evt.Message)
		log.Error(err, "",
			"detected_at", evt.DetectedAt,
			"request_url", evt.Context.HttpRequest.URL,
			"rule_id", evt.Rule.ID,
			"block", evt.Rule.IsBlockAction(),
			"meta", evt.Context.Meta,
		)
	}

	return nil
}
