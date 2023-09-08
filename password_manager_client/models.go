package main

import (
	"database/sql"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

var (
	dbHost     = "localhost"
	dbPort     = 5432
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbName     = "postgres"
)

var modelsLogger *log.Logger

func init() {
	modelsLogger = log.New(os.Stdout, "[Models] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	modelsLogger.Printf("Retrieving user by username: %s", username)

	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = $1", username).Scan(&hashedPassword)

	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	} else if err != nil {
		return nil, err
	}

	return &User{Username: username, Password: hashedPassword}, nil
}

func CreateUser(db *sql.DB, username, password string) error {
	modelsLogger.Printf("Creating new user: %s", username)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		modelsLogger.Printf("Error generating password hash: %v", err)
		return err
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, string(hashedPassword))
	if err != nil {
		modelsLogger.Printf("Error inserting new user into the database: %v", err)
		return err
	}

	return nil
}

func AuthenticateUser(db *sql.DB, username, password string) (bool, error) {
	modelsLogger.Printf("Authenticating user: %s", username)

	user, err := GetUserByUsername(db, username)
	if err != nil {
		modelsLogger.Printf("Error retrieving user: %v", err)
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		modelsLogger.Printf("Authentication failed for user: %s", username)
		return false, nil
	}

	modelsLogger.Printf("User authenticated: %s", username)
	return true, nil
}
