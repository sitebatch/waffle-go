package waffle_test

import (
	_ "github.com/mattn/go-sqlite3"

	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sitebatch/waffle-go"
	"github.com/sitebatch/waffle-go/action"
	waffleSQL "github.com/sitebatch/waffle-go/contrib/database/sql"
	ginWaf "github.com/sitebatch/waffle-go/contrib/gin-gonic/gin"
	"github.com/sitebatch/waffle-go/waf"
	"github.com/stretchr/testify/assert"
)

var database *sql.DB

type mockEventExporter struct {
	events []waf.DetectionEvent
}

func (m *mockEventExporter) Export(_ context.Context, events waf.ReadOnlyDetectionEvents) error {
	m.events = append(m.events, events.Events()...)

	return nil
}

func TestStart_Integration(t *testing.T) {
	t.Parallel()

	setupDB(t)
	r := setupRouter()

	testCases := map[string]struct {
		req                  *http.Request
		wantStatusCode       int
		wantResponseBody     string
		wantDetectionRuleIDs []string
	}{
		"Successful Login": {
			req: func() *http.Request {
				form := url.Values{}
				form.Add("email", "user@example.com")
				form.Add("password", "password")
				body := bytes.NewBufferString(form.Encode())
				r := httptest.NewRequest("POST", "/login", body)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			wantStatusCode:       200,
			wantResponseBody:     `{"message":"login successful"}`,
			wantDetectionRuleIDs: []string{},
		},
		"Failed Login": {
			req: func() *http.Request {
				form := url.Values{}
				form.Add("email", "user@example.com")
				form.Add("password", "wrongpassword")
				body := bytes.NewBufferString(form.Encode())
				r := httptest.NewRequest("POST", "/login", body)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			wantStatusCode:       403,
			wantResponseBody:     `{"error":"login failed"}`,
			wantDetectionRuleIDs: []string{},
		},
		"Block SQL Injection": {
			req: func() *http.Request {
				form := url.Values{}
				form.Add("email", "' OR 1=1;--")
				form.Add("password", "anything")
				body := bytes.NewBufferString(form.Encode())
				r := httptest.NewRequest("POST", "/login", body)
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			wantStatusCode:       403,
			wantResponseBody:     `request blocked`,
			wantDetectionRuleIDs: []string{"sql-injection-exploited"},
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			eventExporter := &mockEventExporter{}
			waffle.SetExporter(eventExporter)
			waffle.SetBlockResponseTemplateHTML([]byte("request blocked"))
			waffle.Start()

			w := httptest.NewRecorder()

			r.ServeHTTP(w, tt.req)
			assert.Equal(t, tt.wantStatusCode, w.Code)
			assert.Equal(t, tt.wantResponseBody, w.Body.String())

			ruleIDs := make([]string, 0, len(eventExporter.events))
			for _, evt := range eventExporter.events {
				ruleIDs = append(ruleIDs, evt.Rule.ID)
			}

			assert.Equal(t, tt.wantDetectionRuleIDs, ruleIDs)
		})
	}
}

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(ginWaf.WafMiddleware())
	r.POST("/login", func(c *gin.Context) {
		loginController(c)
	})
	return r
}

func loginController(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	err := insecureLogin(c.Request.Context(), email, password)
	if err != nil {
		var actionErr *action.BlockError
		if errors.As(err, &actionErr) {
			return
		}

		c.JSON(403, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "login successful",
	})
}

func insecureLogin(ctx context.Context, email, password string) error {
	rows, err := database.QueryContext(ctx, fmt.Sprintf(
		"SELECT * FROM users WHERE email = '%s' AND password = '%s';", email, password,
	))
	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		return nil
	}

	return errors.New("login failed")
}

func setupDB(t *testing.T) {
	t.Helper()

	db, err := waffleSQL.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		panic(err)
	}

	if _, err := db.Exec("CREATE TABLE users(id int, email text, password text);"); err != nil {
		panic(err)
	}

	if _, err := db.Exec("INSERT INTO users(id, email, password) VALUES(1, 'user@example.com', 'password');"); err != nil {
		panic(err)
	}

	database = db
}
