package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq" // PostgreSQL driver
)

var (
	dbHost     = "localhost"
	dbPort     = 5432
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbName     = "postgres"
)

func main() {
	username := flag.String("username", "", "Username")
	action := flag.String("action", "", "Action (create or get)")

	flag.Parse()

	if *username == "" || *action == "" {
		fmt.Println("Usage: main -username <username> -action <action>")
		os.Exit(1)
	}

	db, err := connectToDatabase()
	if err != nil {
		log.Fatalf("Database connection error: %v", err)
	}
	defer db.Close()

	switch *action {
	case "create":
		createUser(db, *username)
	case "get":
		getUser(db, *username)
	default:
		fmt.Println("Invalid action. Use 'create' or 'get'.")
		os.Exit(1)
	}
}

func connectToDatabase() (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	fmt.Println("Connected to the database!")
	return db, nil
}

func createUser(db *sql.DB, username string) {
	// Implement user creation logic here
	fmt.Printf("Creating user with username: %s\n", username)
}

func getUser(db *sql.DB, username string) {
	// Implement user retrieval logic here
	fmt.Printf("Getting user with username: %s\n", username)
}
