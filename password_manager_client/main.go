package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

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

// AccountInfo represents account information
type AccountInfo struct {
	Description string `json:"description"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

var logger *log.Logger
var db *sql.DB
var serverCertPath = "server-cert.pem"
var serverKeyPath = "server-key.pem" 
var caCertPath = "ca-cert.pem"  

// User represents user information
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func createGUI() fyne.Window {
	myApp := app.New()

	window := myApp.NewWindow("Password Manager")

	titleLabel := widget.NewLabel("Welcome to Password Manager")
	descriptionLabel := widget.NewLabel("Manage your passwords securely.")

	newButton := widget.NewButton("New Account", func() {
		// Handle New Account button click
		fmt.Println("New Account button clicked")
	})

	getButton := widget.NewButton("Get Account", func() {
		// Handle Get Account button click
		fmt.Println("Get Account button clicked")
	})

	backupButton := widget.NewButton("Backup", func() {
		// Handle Backup button click
		fmt.Println("Backup button clicked")
	})

	recoverButton := widget.NewButton("Recover", func() {
		// Handle Recover button click
		fmt.Println("Recover button clicked")
	})

	content := container.NewVBox(
		titleLabel,
		descriptionLabel,
		newButton,
		getButton,
		backupButton,
		recoverButton,
	)

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

// ToJSON converts Configuration to JSON format
func (c *Configuration) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ConfigurationFromJSON converts JSON data to Configuration struct
func ConfigurationFromJSON(data []byte) (*Configuration, error) {
	var c Configuration
	err := json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ToJSON converts DatabaseData to JSON format
func (d *DatabaseData) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// DatabaseDataFromJSON converts JSON data to DatabaseData struct
func DatabaseDataFromJSON(data []byte) (*DatabaseData, error) {
	var d DatabaseData
	err := json.Unmarshal(data, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// ToJSON converts AccountInfo to JSON format
func (a *AccountInfo) ToJSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// AccountInfoFromJSON converts JSON data to AccountInfo struct
func AccountInfoFromJSON(data []byte) (*AccountInfo, error) {
	var a AccountInfo
	err := json.Unmarshal(data, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ToJSON converts User to JSON format
func (u *User) ToJSON() ([]byte, error) {
	return json.MarshalIndent(u, "", "  ")
}

// UserFromJSON converts JSON data to User struct
func UserFromJSON(data []byte) (*User, error) {
	var u User
	err := json.Unmarshal(data, &u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// backupCmd defines the "backup" command
var backupCmd = &cobra.Command{
	Use:   "backup [backupPath]",
	Short: "Create a backup of encrypted data",
	Long:  `The backup command allows you to create a backup of your encrypted account data.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		backupPath := args[0]
		config := loadConfiguration("default")
		dbData := retrieveAllFromDatabase()
		backupData := BackupData{Configuration: config, EncryptedData: dbData}
		backupDataJSON, _ := backupData.ToJSON()
		_ = ioutil.WriteFile(backupPath, backupDataJSON, 0644)
	},
}

// recoverCmd defines the "recover" command
var recoverCmd = &cobra.Command{
	Use:   "recover [backupPath]",
	Short: "Recover account data from a backup",
	Long:  `The recover command allows you to recover your account data from a backup file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		backupPath := args[0]
		backupDataJSON, err := ioutil.ReadFile(backupPath)
		if err != nil {
			log.Fatal("Error reading backup file:", err)
		}
		var backupData BackupData
		_ = json.Unmarshal(backupDataJSON, &backupData)
		storeConfiguration("default", backupData.Configuration.SymmetricKey)
		storeAllInDatabase(backupData.EncryptedData)
	},
}

var db *sql.DB
var serverCertPath = "server-cert.pem" 
var serverKeyPath = "server-key.pem"   
var caCertPath = "ca-cert.pem"       

func init() {
	rootCmd.AddCommand(configCmd, newCmd, getCmd, backupCmd, recoverCmd)
}

func main() {
	connectToDatabase()
	initTLS()
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Database connection setup
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

// Server configuration

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
	fmt.Fprintln(w, "Hello, this is a secure server!")
}

// User functions for authentication

func GetUserByUsername(username string) (*User, error) {
	// Implement logic to retrieve user from storage
	return nil, nil
}

func CreateUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	// Implement logic to store new user in storage
	return nil
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
func loadConfiguration(username string) *Configuration {
	file, _ := ioutil.ReadFile("config.json")

	data := new(Configuration)
	_ = json.Unmarshal([]byte(file), data)

	return data
}

// Data structure for user authentication
type User struct {
	Username string
	Password string
}

// ... (other database data structures)

// Encrypt data using a symmetric key
func encryptWithKey(symmetricKey, description, username, password string) (string, error) {
	key, _ := base64.StdEncoding.DecodeString(symmetricKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(description + username + password)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Data structure for configuration
type Configuration struct {
	Username     string
	SymmetricKey string
}

// Data structure for database data
type DatabaseData struct {
	Description   string
	Username      string
	EncryptedData string
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
func retrieveFromDatabase(description string) *databaseData {
	var data databaseData
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

// Data structure for configuration
type configuration struct {
	Username     string
	SymmetricKey string
}

// Data structure for database data
type databaseData struct {
	Description   string
	Username      string
	EncryptedData string
}
