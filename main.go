package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtmiddleware "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	jwtSecret = []byte("your_secret_key")
)

const (
	dbUser     = "praneeth"
	dbPassword = "praneeth"
	dbName     = "auth-app"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}

func main() {
	var err error
	connStr := "user=" + dbUser + " password=" + dbPassword + " dbname=" + dbName + " sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening the database: ", err)
	}
	defer db.Close()
	err = createTableIfNotExists()
	if err != nil {
		log.Fatal("Error creating table: ", err)
	}
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.POST("/signup", signup)
	e.POST("/login", login)
	e.GET("/auto-login", autoLogin)
	r := e.Group("/protected")
	r.Use(jwtmiddleware.WithConfig(jwtmiddleware.Config{
		SigningKey: jwtSecret,
	}))

	r.GET("", protected)

	e.Logger.Fatal(e.Start(":8080"))
}
func createTableIfNotExists() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	)`)
	return err
}

func signup(c echo.Context) error {
	u := new(User)
	if err := c.Bind(u); err != nil {
		return err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Error hashing password"})
	}
	_, err = db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", u.Email, string(hashedPassword))
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "User already exists or database error"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Signup successful"})
}

func login(c echo.Context) error {
	u := new(User)
	if err := c.Bind(u); err != nil {
		return err
	}
	var id int
	var storedHash string
	err := db.QueryRow("SELECT id, password FROM users WHERE email=$1", u.Email).Scan(&id, &storedHash)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid credentials"})
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(u.Password)) != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid credentials"})
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": id,
		"email":   u.Email,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Error generating token"})
	}

	return c.JSON(http.StatusOK, echo.Map{"token": tokenString})
}

func protected(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome " + email})
}
