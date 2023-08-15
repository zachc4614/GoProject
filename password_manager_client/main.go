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
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type EncryptedPayload struct {
	Description string `json:"description"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Configuration struct {
	Username     string `json:"username"`
	SymmetricKey string `json:"symmetric_key"`
}

type DatabaseData struct {
	Description   string `json:"description"`
	Username      string `json:"username"`
	EncryptedData string `json:"encrypted_data"`
}

var logger *log.Logger
var serverCertPath = "server-cert.pem"
var serverKeyPath = "server-key.pem"
var caCertPath = "ca-cert.pem"

func main() {
	logger = log.New(os.Stdout, "[PasswordManager] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("Panic: %v\n%s", r, debug.Stack())
		}
	}()
	db := connectToDatabase()
	defer db.Close()
	initTLS()
	guiWindow := createGUI()
	guiWindow.ShowAndRun()
}

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

func connectToDatabase() *sql.DB {
	connStr := "user=username dbname=mydb sslmode=disable password=mypassword"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		logger.Fatal("Database connection error:", err)
	}
	if err = db.Ping(); err != nil {
		logger.Fatal("Database ping error:", err)
	}
	logger.Println("Connected to the database!")
	return db
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
	if r.Method != http.MethodGet {
		errorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	fmt.Fprintln(w, "Hello, this is a secure server!")
}

func storeConfiguration(username, symmetricKey string) {
	data := &Configuration{
		Username:     username,
		SymmetricKey: symmetricKey,
	}
	file, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		logger.Println("Error marshaling configuration:", err)
		return
	}
	err = ioutil.WriteFile("config.json", file, 0644)
	if err != nil {
		logger.Println("Error writing configuration to file:", err)
	}
}

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

func storeInDatabase(db *sql.DB, description, username, encryptedData string) error {
	query := `INSERT INTO accounts(description, username, encrypted_data) VALUES($1, $2, $3)`
	_, err := db.Exec(query, description, username, encryptedData)
	return err
}

func retrieveFromDatabase(db *sql.DB, description string) (*DatabaseData, error) {
	data := new(DatabaseData)
	query := `SELECT description, username, encrypted_data FROM accounts WHERE description=$1`
	err := db.QueryRow(query, description).Scan(&data.Description, &data.Username, &data.EncryptedData)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func decryptWithKey(symmetricKey, encryptedData string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(symmetricKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	var result EncryptedPayload
	if err := json.Unmarshal(ciphertext, &result); err != nil {
		return "", err
	}
	return result.Password, nil
}

func errorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "{\"error\": \"%s\"}", message)
}
