package main

import (
	"errors"
	"log"
	"os"
	"golang.org/x/crypto/bcrypt"
	"database/sql"
)

var modelsLogger *log.Logger

func init() {
	modelsLogger = log.New(os.Stdout, "[Models] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
}

func GetUserByUsername(username string) (*User, error) {
	modelsLogger.Printf("Retrieving user by username: %s", username)
	
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = $1", username).Scan(&hashedPassword)
	
	if err == sql.ErrNoRows {
		return nil, errors.New("authentication failed")
	} else if err != nil {
		return nil, err
	}

	return &User{Username: username, Password: hashedPassword}, nil
}

func CreateUser(username, password string) error {
	modelsLogger.Printf("Creating new user: %s", username)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		modelsLogger.Printf("Error generating password hash: %v", err)
		return err
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, string(hashedPassword))
	if err != nil {
		modelsLogger.Printf("Error inserting new user into database: %v", err)
		return err
	}

	return nil
}

func AuthenticateUser(username, password string) (bool, error) {
	modelsLogger.Printf("Authenticating user: %s", username)

	user, err := GetUserByUsername(username)
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

// DatabaseData represents data stored in the database
type DatabaseData struct {
	Description   string `json:"description"`
	Username      string `json:"username"`
	EncryptedData string `json:"encrypted_data"`
}

// AccountInfo represents account information
type AccountInfo struct {
	Description string `json:"description"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}
