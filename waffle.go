package waffle

import (
	"context"

	"github.com/sitebatch/waffle-go/action"
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
)

type Config struct {
	Debug             bool
	OverrideRulesJSON []byte
}

func defaultConfig() *Config {
	return &Config{Debug: false}
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
		log.Info("waffle: loaded custom rules")
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

func WithDebug() Options {
	return func(c *Config) {
		c.Debug = true
		log.SetLevel(log.LevelDebug)
		log.Debug("waffle: debug mode enabled")
	}
}

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

func Start(opts ...Options) {
	action.InitResponseWriterFeature()
	c := defaultConfig()
	for _, opt := range opts {
		opt(c)
	}

	w := &Waffle{
		overrideRulesJSON: c.OverrideRulesJSON,
	}
	err := w.start()
	if err != nil {
		log.Error("Failed to start waffle: %v", err)
		return
	}

	log.Info("waffle: started")
}

func SetUser(ctx context.Context, userID string) error {
	op, found := operation.FindOperation[waf.WafOperation](ctx)
	if !found {
		return nil
	}

	op.SetMeta(string(waf.UserID), userID)
	return nil
}
