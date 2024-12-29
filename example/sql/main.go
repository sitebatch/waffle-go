package main

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/gin-gonic/gin"
	"github.com/sitebatch/waffle-go"
	waffleSQL "github.com/sitebatch/waffle-go/contrib/database/sql"
	ginWaf "github.com/sitebatch/waffle-go/contrib/gin-gonic/gin"
)

var database *sql.DB

func init() {
	setupDB()
}

func main() {
	waffle.Start(waffle.WithDebug())

	r := gin.Default()

	r.Use(ginWaf.WafMiddleware())

	r.POST("/login", func(c *gin.Context) {
		loginController(c)
	})

	r.POST("/insecure-login", func(c *gin.Context) {
		insecureLoginController(c)
	})

	r.Run(":8000")
}

func loginController(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	err := login(c.Request.Context(), email, password)
	if err != nil {
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
	})
}

func insecureLoginController(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	err := insecureLogin(c.Request.Context(), email, password)
	if err != nil {
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
	})
}

func login(ctx context.Context, email, password string) error {
	_, err := database.QueryContext(ctx, "SELECT * FROM users WHERE email = ? AND password = ?;", email, password)
	if err != nil {
		return err
	}

	return nil
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

func setupDB() {
	driverName, err := waffleSQL.Register("sqlite3")
	if err != nil {
		panic(err)
	}

	db, err := sql.Open(driverName, "file::memory:?cache=shared")
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
