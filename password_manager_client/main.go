package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq" // Assuming you're using PostgreSQL
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type EncryptedPayload struct {
	Description string `json:"description"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}
// User represents user information
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Configuration represents the user's configuration
type Configuration struct {
	Username     string `json:"username"`
	SymmetricKey string `json:"symmetric_key"`
}

// DatabaseData represents the encrypted data stored in the database
type DatabaseData struct {
	Description   string `json:"description"`
	Username      string `json:"username"`
	EncryptedData string `json:"encrypted_data"`
}

// Global variables
var logger *log.Logger
var db *sql.DB
var serverCertPath = "server-cert.pem"
var serverKeyPath = "server-key.pem"
var caCertPath = "ca-cert.pem"

func createGUI() fyne.Window {
	myApp := app.New()
	window := myApp.NewWindow("Password Manager")
	titleLabel := widget.NewLabel("Welcome to Password Manager")
	descriptionLabel := widget.NewLabel("Manage your passwords securely.")
	newButton := widget.NewButton("New Account", func() { fmt.Println("New Account button clicked") })
	getButton := widget.NewButton("Get Account", func() { fmt.Println("Get Account button clicked") })
	backupButton := widget.NewButton("Backup", func() { fmt.Println("Backup button clicked") })
	recoverButton := widget.NewButton("Recover", func() { fmt.Println("Recover button clicked") })
	content := container.NewVBox(titleLabel, descriptionLabel, newButton, getButton, backupButton, recoverButton)
	window.SetContent(content)
	return window
}

func main() {
	logger = log.New(os.Stdout, "[PasswordManager] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("Panic: %v\n%s", r, debug.Stack())
		}
	}()
	connectToDatabase()
	initTLS()
	guiWindow := createGUI()
	guiWindow.ShowAndRun()
}

func connectToDatabase() {
	// Set your database connection parameters here
	connStr := "user=username dbname=mydb sslmode=disable password=mypassword"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		logger.Fatal("Database connection error:", err)
	}
	if err = db.Ping(); err != nil {
		logger.Fatal("Database ping error:", err)
	}
	logger.Println("Connected to the database!")
}

func initTLS() {
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		log.Fatalf("Error loading server key pair: %s", err)
	}
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("Error reading CA certificate: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	http.HandleFunc("/", handleRequest)
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}
	go func() {
		log.Println("Starting server on :8443...")
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Error starting server: %s", err)
		}
	}()
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Example error handling
	if r.Method != http.MethodGet {
		errorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	fmt.Fprintln(w, "Hello, this is a secure server!")
}
// User functions for authentication

func GetUserByUsername(username string) (*User, error) {
	user := &User{}
	query := "SELECT username, password FROM users WHERE username=$1"
	err := db.QueryRow(query, username).Scan(&user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No matching user found
		}
		return nil, err // Some other database error
	}
	return user, nil
}

func CreateUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	query := "INSERT INTO users(username, password) VALUES($1, $2)"
	_, err = db.Exec(query, username, string(hashedPassword))
	return err
}

func AuthenticateUser(username, password string) (bool, error) {
	user, err := GetUserByUsername(username)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Store configuration data to a file
func storeConfiguration(username, symmetricKey string) {
	data := &Configuration{
		Username:     username,
		SymmetricKey: symmetricKey,
	}

	file, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile("config.json", file, 0644)
}

// Load configuration data from a file
func loadConfiguration(username string) (*Configuration, error) {
	file, err := ioutil.ReadFile("config.json")
	if err != nil {
		return nil, err
	}

	data := new(Configuration)
	err = json.Unmarshal(file, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Encrypt data using a symmetric key
func encryptWithKey(symmetricKey string, payload *EncryptedPayload) (string, error) {
	key, err := base64.StdEncoding.DecodeString(symmetricKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Store encrypted data in the database
func storeInDatabase(description, username, encryptedData string) {
	query := `INSERT INTO accounts(description, username, encrypted_data) VALUES($1, $2, $3)`
	_, err := db.Exec(query, description, username, encryptedData)
	if err != nil {
		log.Fatal(err)
	}
}

// Retrieve encrypted data from the database
func retrieveFromDatabase(description string) *DatabaseData {
	var data DatabaseData // Fixed variable type name
	query := `SELECT description, username, encrypted_data FROM accounts WHERE description=$1`
	row := db.QueryRow(query, description)
	err := row.Scan(&data.Description, &data.Username, &data.EncryptedData)
	if err != nil {
		log.Fatal(err)
	}
	return &data
}

// Decrypt data using a symmetric key
func decryptWithKey(symmetricKey, encryptedData string) (string, error) {
	key, _ := base64.StdEncoding.DecodeString(symmetricKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext, _ := base64.URLEncoding.DecodeString(encryptedData)

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("Ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	fmt.Fprintln(w, message)
}
