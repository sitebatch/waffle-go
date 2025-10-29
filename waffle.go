package waffle

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/sitebatch/waffle-go/exporter"
	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/handler/response"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/listener/account_takeover"
	"github.com/sitebatch/waffle-go/internal/listener/graphql"
	"github.com/sitebatch/waffle-go/internal/listener/http"
	"github.com/sitebatch/waffle-go/internal/listener/os"
	"github.com/sitebatch/waffle-go/internal/listener/sql"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/sitebatch/waffle-go/waf/wafcontext"
)

var listeners = []listener.NewListener{
	http.NewHTTPSecurity,
	http.NewHTTPClientSecurity,
	graphql.NewGraphqlSecurity,
	sql.NewSQLSecurity,
	os.NewFileSecurity,
	account_takeover.NewAccountTakeoverSecurity,
}

type Config struct {
	RuleJSON []byte
}

type Waffle struct {
	listeners []listener.Listener
	ruleJSON  []byte
}

type Options func(*Config)

func WithRule(ruleJSON []byte) Options {
	return func(c *Config) {
		c.RuleJSON = ruleJSON
	}
}

// Start initializes and starts Waffle with the provided options.
func Start(opts ...Options) error {
	response.InitResponseWriterFeature()

	c := defaultConfig()
	for _, opt := range opts {
		opt(c)
	}

	w := &Waffle{
		ruleJSON: c.RuleJSON,
	}

	if err := w.start(); err != nil {
		return err
	}

	return nil
}

// SetBlockResponseTemplateHTML sets the HTML template for block responses.
func SetBlockResponseTemplateHTML(html []byte) {
	response.SetBlockResponseTemplateHTML(html)
}

// SetBlockResponseTemplateJSON sets the JSON template for block responses.
func SetBlockResponseTemplateJSON(json []byte) {
	response.SetBlockResponseTemplateJSON(json)
}

// SetLogger sets a global logger for Waffle.
func SetLogger(logger logr.Logger) {
	log.SetLogger(logger)
}

// SetErrorHandler sets a global error handler for Waffle.
//
// Waffle monitors applications for potential attacks by inspecting input values and generating test data.
// Typically, the operations performed by Waffle are not essential to an application's core business logic.
// Therefore, errors occurring within Waffle are designed to not affect the application's normal operation.
// By default, errors are logged, but you can define custom logic to handle and record these errors for monitoring purposes.
func SetErrorHandler(h handler.ErrorHandler) {
	handler.SetErrorHandler(h)
}

// SetExporter sets a exporter of WAF detection event.
//
// Waffle can export WAF detection events to any desired location using the provided exporter.
// By default, Waffle uses a no-operation exporter that does not export any events.
// You can implement your own exporter by implementing the exporter.EventExporter interface
// and set it using this function.
func SetExporter(eventExporter exporter.EventExporter) {
	exporter.SetExporter(eventExporter)
}

func SetUser(ctx context.Context, userID string) error {
	op, found := operation.FindOperation[waf.WafOperation](ctx)
	if !found {
		return nil
	}

	op.SetMeta(string(wafcontext.UserID), userID)
	return nil
}

func defaultConfig() *Config {
	return &Config{
		RuleJSON: rule.DefaultRuleSetJSON(),
	}
}

func (w *Waffle) start() error {
	if err := rule.LoadRuleSet(w.ruleJSON); err != nil {
		return err
	}

	rootOp := operation.NewRootOperation()
	newListeners := make([]listener.Listener, len(listeners))

	for _, newListener := range listeners {
		l, err := newListener(rootOp)
		if err != nil {
			return err
		}

		newListeners = append(newListeners, l)
	}

	w.listeners = newListeners
	operation.InitRootOperation(rootOp)

	return nil
}
