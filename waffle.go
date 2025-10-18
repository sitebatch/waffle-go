package waffle

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/sitebatch/waffle-go/action"
	"github.com/sitebatch/waffle-go/handler"
	"github.com/sitebatch/waffle-go/internal/emitter/waf"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/exporter"
	"github.com/sitebatch/waffle-go/internal/emitter/waf/wafcontext"
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/listener/account_takeover"
	"github.com/sitebatch/waffle-go/internal/listener/graphql"
	"github.com/sitebatch/waffle-go/internal/listener/http"
	"github.com/sitebatch/waffle-go/internal/listener/os"
	"github.com/sitebatch/waffle-go/internal/listener/sql"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type Config struct {
	OverrideRulesJSON []byte
}

func defaultConfig() *Config {
	return &Config{}
}

type Waffle struct {
	listeners         []listener.Listener
	overrideRulesJSON []byte
}

var listeners = []listener.NewListener{
	http.NewHTTPSecurity,
	http.NewHTTPClientSecurity,
	graphql.NewGraphqlSecurity,
	sql.NewSQLSecurity,
	os.NewFileSecurity,
	account_takeover.NewAccountTakeoverSecurity,
}

func (w *Waffle) start() error {
	if len(w.overrideRulesJSON) > 0 {
		if err := rule.LoadRules(w.overrideRulesJSON); err != nil {
			return err
		}
	} else {
		if err := rule.LoadDefaultRules(); err != nil {
			return err
		}
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

type Options func(*Config)

func WithOverrideRules(ruleJSON []byte) Options {
	return func(c *Config) {
		c.OverrideRulesJSON = ruleJSON
	}
}

func WithCustomBlockedResponse(responseBodyHTML []byte, responseBodyJSON []byte) Options {
	return func(c *Config) {
		if len(responseBodyHTML) != 0 {
			action.RegisterBlockResponseTemplateHTML(responseBodyHTML)
		}
		if len(responseBodyJSON) != 0 {
			action.RegisterBlockResponseTemplateJSON(responseBodyJSON)
		}
	}
}

func Start(opts ...Options) error {
	action.InitResponseWriterFeature()
	c := defaultConfig()
	for _, opt := range opts {
		opt(c)
	}

	w := &Waffle{
		overrideRulesJSON: c.OverrideRulesJSON,
	}
	SetExporterProvider(exporter.ExporterNameStdout)
	err := w.start()
	if err != nil {
		return err
	}

	return nil
}

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

func SetExporterProvider(name waf.ExporterName) error {
	switch name {
	case exporter.ExporterNameStdout:
		waf.SetExporter(exporter.NewStdoutExporter())
		return nil
	default:
		return fmt.Errorf("unknown exporter name: %s", name)
	}
}

func SetUser(ctx context.Context, userID string) error {
	op, found := operation.FindOperation[waf.WafOperation](ctx)
	if !found {
		return nil
	}

	op.SetMeta(string(wafcontext.UserID), userID)
	return nil
}
