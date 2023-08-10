package main

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

var userStore map[string]string // In-memory store for users

func initStore() {
	userStore = make(map[string]string)
}

func GetUserByUsername(username string) (*User, error) {
	modelsLogger.Printf("Retrieving user by username: %s", username)
	if hashedPassword, found := userStore[username]; found {
		return &User{Username: username, Password: hashedPassword}, nil
	}
	return nil, errors.New("user not found")
}

func CreateUser(username, password string) error {
	modelsLogger.Printf("Creating new user: %s", username)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		modelsLogger.Printf("Error generating password hash: %v", err)
		return err
	}
	userStore[username] = string(hashedPassword)
	return nil
}

func AuthenticateUser(username, password string) (bool, error) {
	modelsLogger.Printf("Authenticating user: %s", username)
	user, err := GetUserByUsername(username)
	if err != nil {
		modelsLogger.Printf("Error retrieving user: %v", err)
		return false, err
	}

	if user == nil {
		modelsLogger.Printf("User not found: %s", username)
		return false, nil
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
