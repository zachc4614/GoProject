package main

import (
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

// User represents user information
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GetUserByUsername retrieves user by username
func GetUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT username, password FROM users WHERE username = $1", username).Scan(&user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUser stores a new user
func CreateUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, string(hashedPassword))
	return err
}

// AuthenticateUser authenticates user credentials
func AuthenticateUser(username, password string) (bool, error) {
	user, err := GetUserByUsername(username)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, errors.New("user not found")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return false, nil
	}
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
