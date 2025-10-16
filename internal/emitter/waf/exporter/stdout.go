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
	for _, evt := range event.Events() {
		log.Info("WAF Detection Event",
			"time", evt.DetectedAt,
			"rule_id", evt.Rule.ID,
			"block", evt.Rule.IsBlockAction(),
			"inspector", evt.Inspector,
			"message", evt.Message,
			"payload", evt.Payload,
			"http_request", evt.Context.HttpRequest,
			"meta", evt.Context.Meta,
		)
	}

	return nil
}
