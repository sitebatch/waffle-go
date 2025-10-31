package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sitebatch/waffle-go"
	waffleSQL "github.com/sitebatch/waffle-go/contrib/database/sql"
	waffleHttp "github.com/sitebatch/waffle-go/contrib/net/http"
	"github.com/sitebatch/waffle-go/exporter"
	"github.com/sitebatch/waffle-go/waf"
)

var database *sql.DB

func init() {
	if err := setupDB(); err != nil {
		log.Fatalf("failed to setup database: %v", err)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      newHTTPHandler(),
	}

	waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))
	waffle.SetExporter(exporter.NewStdoutExporter())

	if err := waffle.Start(); err != nil {
		log.Fatalf("failed to start waffle: %v", err)
	}

	log.Printf("starting server at %s", srv.Addr)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-srvErr:
		log.Fatal(err)
	case <-ctx.Done():
		stop()
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		log.Fatalf("server shutdown failed: %v", err)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	if err := login(r.Context(), email, password); err != nil {
		if waf.IsSecurityBlockingError(err) {
			return
		}

		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "login successful")
}

func login(ctx context.Context, email, password string) error {
	rows, err := database.QueryContext(ctx, fmt.Sprintf(
		"SELECT * FROM users WHERE email = '%s' AND password = '%s';", email, password,
	))
	if err != nil {
		return err
	}

	defer rows.Close()

	if !rows.Next() {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r)
	})

	handler := waffleHttp.WafMiddleware(mux)
	return handler
}

func setupDB() error {
	db, err := waffleSQL.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE users(id int, email text, password text);"); err != nil {
		return err
	}

	if _, err := db.Exec("INSERT INTO users(id, email, password) VALUES(1, 'user@example.com', 'password');"); err != nil {
		return err
	}

	database = db

	return nil
}
