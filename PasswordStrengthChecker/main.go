package main

import (
	"fmt"
	"strings"
	"math"
	"unicode"
)

func main() {
	fmt.Println("Password Strength Checker")
	fmt.Println("-------------------------")

	password := readPassword()
	strengthScore := calculatePasswordStrength(password)
	strengthRating := getPasswordStrengthRating(strengthScore)

	if strengthScore <= 1 {
		suggestions := getPasswordSuggestions(password)
		fmt.Println("Password is weak. Consider the following suggestions:")
		for _, suggestion := range suggestions {
			fmt.Println("-", suggestion)
		}
	}

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
	leetCharacters := "4bcd3fgh1jklmn0pqr57uvwxy2"

	// Check for special characters
	for _, char := range password {
		if strings.ContainsRune(specialCharacters, char) {
			return true
		}
	}

	// Check for leet speak substitutions
	for _, char := range password {
		if unicode.IsLetter(char) {
			leetIndex := int(unicode.ToLower(char)) - 'a'
			if leetIndex >= 0 && leetIndex < len(leetCharacters) {
				leetEquivalent := rune(leetCharacters[leetIndex])
				if strings.ContainsRune(password, leetEquivalent) {
					return true
				}
			}
		}
	}

	return false
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

func calculateEntropy(password string) float64 {
	charsetSize := 0
	entropy := 0.0

	if hasUpperCaseLetter(password) {
		charsetSize += 26
		entropy += math.Log2(26)
	}

	if hasLowerCaseLetter(password) {
		charsetSize += 26
		entropy += math.Log2(26)
	}

	if hasNumber(password) {
		charsetSize += 10
		entropy += math.Log2(10)
	}

	if hasSpecialCharacter(password) {
		charsetSize += 32 // Assuming 32 possible special characters
		entropy += math.Log2(32)
	}

	return float64(charsetSize) * entropy
}

func getPasswordSuggestions(password string) []string {
	var suggestions []string

	if len(password) < 8 {
		suggestions = append(suggestions, "Use at least 8 characters")
	}

	if !hasUpperCaseLetter(password) {
		suggestions = append(suggestions, "Include at least one uppercase letter")
	}

	if !hasLowerCaseLetter(password) {
		suggestions = append(suggestions, "Include at least one lowercase letter")
	}

	if !hasNumber(password) {
		suggestions = append(suggestions, "Include at least one number")
	}

	if !hasSpecialCharacter(password) {
		suggestions = append(suggestions, "Include at least one special character")
	}

	if isCommonPassword(password) {
		suggestions = append(suggestions, "Avoid using common or easily guessable passwords")
	}

	return suggestions
}

func isCommonPassword(password string) bool {
	commonPasswords := []string{
		"password", "123456", "qwerty", "admin", "letmein", "monkey", "abc123",
		"iloveyou", "123123", "password1", "qwertyuiop", "welcome", "login",
		"password123", "12345", "sunshine", "1234567890", "princess", "admin123",
		"password!@#", "baseball", "password1", "dragon", "trustno1",
	}

	password = strings.ToLower(password)
	for _, commonPwd := range commonPasswords {
		if password == commonPwd {
			return true
		}
	}

	return false
}
