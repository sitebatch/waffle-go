package exporter

import (
	"context"

	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/log"
)

var (
	ExporterNameStdout waf.ExporterName = "stdout"
)

type StdoutExporter struct{}

func NewStdoutExporter() *StdoutExporter {
	return &StdoutExporter{}
}

func (e *StdoutExporter) Export(ctx context.Context, event waf.ReadOnlyDetectionEvents) error {
	for _, events := range event.Events() {
		log.Info("WAF Detection Event",
			"time", events.Time,
			"rule_id", events.Rule.ID,
			"inspector", events.Inspector,
			"message", events.Message,
			"payload", events.Payload,
			"http_request", events.Context.HttpRequest,
			"meta", events.Context.Meta,
		)
	}

	return nil
}
