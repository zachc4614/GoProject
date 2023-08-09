package main

import (
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"log"
)

var modelsLogger *log.Logger

// User represents user information
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GetUserByUsername retrieves user by username
func GetUserByUsername(username string) (*User, error) {
	modelsLogger.Printf("Retrieving user by username: %s", username)

	// Implement your logic to retrieve user from storage (e.g., database)
	// Return user and nil if found, or nil and an error if not found

	return nil, nil
}

// CreateUser stores a new user
func CreateUser(username, password string) error {
	modelsLogger.Printf("Creating new user: %s", username)

	// Hash the password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		modelsLogger.Printf("Error generating password hash: %v", err)
		return err
	}

	// Implement your logic to store new user in storage (e.g., database)

	return nil
}

// AuthenticateUser authenticates user credentials
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

// Configuration represents the configuration information
type Configuration struct {
	Username     string `json:"username"`
	SymmetricKey string `json:"symmetric_key"`
}

// ToJSON converts Configuration struct to JSON
func (c *Configuration) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ConfigurationFromJSON parses JSON to create Configuration struct
func ConfigurationFromJSON(data []byte) (*Configuration, error) {
	var c Configuration
	err := json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// DatabaseData represents data stored in the database
type DatabaseData struct {
	Description   string `json:"description"`
	Username      string `json:"username"`
	EncryptedData string `json:"encrypted_data"`
}

// ToJSON converts DatabaseData struct to JSON
func (d *DatabaseData) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// DatabaseDataFromJSON parses JSON to create DatabaseData struct
func DatabaseDataFromJSON(data []byte) (*DatabaseData, error) {
	var d DatabaseData
	err := json.Unmarshal(data, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// AccountInfo represents account information
type AccountInfo struct {
	Description string `json:"description"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

// ToJSON converts AccountInfo struct to JSON
func (a *AccountInfo) ToJSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// AccountInfoFromJSON parses JSON to create AccountInfo struct
func AccountInfoFromJSON(data []byte) (*AccountInfo, error) {
	var a AccountInfo
	err := json.Unmarshal(data, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
