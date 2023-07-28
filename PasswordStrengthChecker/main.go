package main

import (
	"fmt"
	"strings"
)

func main() {
	fmt.Println("Password Strength Checker")
	fmt.Println("-------------------------")

	password := readPassword()
	strengthScore := calculatePasswordStrength(password)
	strengthRating := getPasswordStrengthRating(strengthScore)

	fmt.Printf("Password Strength: %s\n", strengthRating)
}

func readPassword() string {
	fmt.Print("Enter your password: ")
	var password string
	fmt.Scanln(&password)
	return password
}

func calculatePasswordStrength(password string) int {
	strength := 0

	// Criteria checks
	if len(password) >= 8 {
		strength++
	}

	if hasUpperCaseLetter(password) {
		strength++
	}

	if hasLowerCaseLetter(password) {
		strength++
	}

	if hasNumber(password) {
		strength++
	}

	if hasSpecialCharacter(password) {
		strength++
	}

	return strength
}

func hasUpperCaseLetter(password string) bool {
	return strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func hasLowerCaseLetter(password string) bool {
	return strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
}

func hasNumber(password string) bool {
	return strings.ContainsAny(password, "0123456789")
}

func hasSpecialCharacter(password string) bool {
	specialCharacters := "!@#$%^&*()_+{}[]:;<>,.?/~`"
	return strings.ContainsAny(password, specialCharacters)
}

func getPasswordStrengthRating(strength int) string {
	switch strength {
	case 0, 1:
		return "Weak"
	case 2:
		return "Moderate"
	case 3, 4:
		return "Strong"
	default:
		return "Very Strong"
	}
}
