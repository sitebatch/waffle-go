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

func TestStart_Integration(t *testing.T) {
	t.Parallel()

	setupDB(t)

	r := setupRouter()
	waffle.Start()

	testCases := map[string]struct {
		req                *http.Request
		wantStatusCode     int
		wantResponseBody   string
		wantDetectionEvent waf.ReadOnlyDetectionEvents
	}{
		"Successful Login": {
			req:                httptest.NewRequest("POST", "/login", bytes.NewBufferString("email=user@example.com&password=password")),
			wantStatusCode:     200,
			wantResponseBody:   `{"message":"login successful"}`,
			wantDetectionEvent: nil,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r.ServeHTTP(w, tt.req)
			assert.Equal(t, tt.wantStatusCode, w.Code)
			assert.Equal(t, tt.wantResponseBody, w.Body.String())
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

		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "login successful",
	})
}

func insecureLogin(ctx context.Context, email, password string) error {
	_, err := database.QueryContext(ctx, fmt.Sprintf(
		"SELECT * FROM users WHERE email = '%s' AND password = '%s';", email, password,
	))
	if err != nil {
		return err
	}

	return nil
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
