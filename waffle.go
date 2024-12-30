package waffle

import (
	"github.com/sitebatch/waffle-go/internal/listener"
	"github.com/sitebatch/waffle-go/internal/listener/account_takeover"
	"github.com/sitebatch/waffle-go/internal/listener/http"
	"github.com/sitebatch/waffle-go/internal/listener/os"
	"github.com/sitebatch/waffle-go/internal/listener/sql"
	"github.com/sitebatch/waffle-go/internal/log"
	"github.com/sitebatch/waffle-go/internal/operation"
	"github.com/sitebatch/waffle-go/internal/rule"
)

type Config struct {
	Debug bool
}

func defaultConfig() *Config {
	return &Config{Debug: false}
}

type Waffle struct {
	listeners []listener.Listener
}

var listeners = []listener.NewListener{
	http.NewHTTPSecurity,
	http.NewHTTPClientSecurity,
	sql.NewSQLSecurity,
	os.NewFileSecurity,
	account_takeover.NewAccountTakeoverSecurity,
}

func (w *Waffle) start() error {
	err := rule.LoadDefaultRules()
	if err != nil {
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

type Options func(*Config)

func WithDebug() Options {
	return func(c *Config) {
		c.Debug = true
		log.SetLevel(log.LevelDebug)
		log.Debug("waffle: debug mode enabled")
	}
}

func Start(opts ...Options) {
	c := defaultConfig()
	for _, opt := range opts {
		opt(c)
	}

	w := &Waffle{}
	err := w.start()
	if err != nil {
		log.Error("Failed to start waffle: %v", err)
		return
	}

	log.Info("waffle: started")
}
