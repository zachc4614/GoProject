package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "pass-man-client",
	Short: "A password manager client tool",
	Long: `A password manager client tool. Complete documentation is available at http://pass-man-client.io`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use pass-man-client with commands: config, new, get")
	},
}

var configCmd = &cobra.Command{
	Use:   "config [username] [password]",
	Short: "Configure master username and password",
	Long:  `The config command allows you to set the master username and password.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		password := args[1]

		symmetricKey := generateSymmetricKey(password)
		storeConfiguration(username, symmetricKey)
	},
}

var newCmd = &cobra.Command{
	Use:   "new [description] [username] [password]",
	Short: "Create new account information",
	Long:  `The new command allows you to store new account information including description, username, and an optional password.`,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		description := args[0]
		username := args[1]
		password := ""
		if len(args) > 2 {
			password = args[2]
		}

		config := loadConfiguration(username)
		encryptedData, _ := encryptWithKey(config.SymmetricKey, description, username, password)
		storeInDatabase(description, username, encryptedData)
	},
}

var getCmd = &cobra.Command{
	Use:   "get [description]",
	Short: "Get account information",
	Long:  `The get command allows you to fetch account information based on its description.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		description := args[0]

		dbData := retrieveFromDatabase(description)
		config := loadConfiguration(dbData.Username)
		accountInfo, _ := decryptWithKey(config.SymmetricKey, dbData.EncryptedData)
		fmt.Println("Account Info:", accountInfo)
	},
}

func init() {
	rootCmd.AddCommand(configCmd, newCmd, getCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func generateSymmetricKey(password string) string {
	salt := []byte("somesalt") // This should be unique for each user in production application
	key := pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(key)
}

func storeConfiguration(username, symmetricKey string) {
	data := &configuration{
		Username:     username,
		SymmetricKey: symmetricKey,
	}

	file, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile("config.json", file, 0644)
}

func loadConfiguration(username string) *configuration {
	file, _ := ioutil.ReadFile("config.json")

	data := new(configuration)
	_ = json.Unmarshal([]byte(file), data)

	return data
}

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

func storeInDatabase(description, username, encryptedData string) {
	dbData := &databaseData{
		Description:   description,
		Username:      username,
		EncryptedData: encryptedData,
	}

	file, _ := ioutil.ReadFile("database.json")
	var db []*databaseData
	_ = json.Unmarshal([]byte(file), &db)
	db = append(db, dbData)

	file, _ = json.MarshalIndent(db, "", " ")
	_ = ioutil.WriteFile("database.json", file, 0644)
}

func retrieveFromDatabase(description string) *databaseData {
	file, _ := ioutil.ReadFile("database.json")

	var db []*databaseData
	_ = json.Unmarshal([]byte(file), &db)

	for _, dbData := range db {
		if dbData.Description == description {
			return dbData
		}
	}

	return &databaseData{}
}

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

type configuration struct {
	Username     string
	SymmetricKey string
}

type databaseData struct {
	Description   string
	Username      string
	EncryptedData string
}
