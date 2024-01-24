package passwords

import (
	"fmt"
)

const (
	// LowercaseLetters is the list of lowercase characters.
	LowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
	// UppercaseLetters is the list of uppercase characters.
	UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// Digits is the list of digits characters.
	Digits = "0123456789"
	// Symbols is the list of symbols characters.
	Symbols = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"

	maxRequiredAlphabets = 4
)

// Policy describes the requirements for the password.
type Policy struct {
	MinLength int
	MaxLength int

	RequireLowercase bool
	RequireUppercase bool
	RequireDigit     bool
	RequireSymbol    bool
}

// NewStrongPolicy generates a Policy instance with all required flags set to true.
func NewStrongPolicy(minLen, maxLen int) Policy {
	return Policy{
		MinLength:        minLen,
		MaxLength:        maxLen,
		RequireLowercase: true,
		RequireUppercase: true,
		RequireDigit:     true,
		RequireSymbol:    true,
	}
}

func (p Policy) Validate() error {
	var differentTypesIncluded int

	if p.RequireLowercase {
		differentTypesIncluded++
	}

	if p.RequireUppercase {
		differentTypesIncluded++
	}

	if p.RequireDigit {
		differentTypesIncluded++
	}

	if p.RequireSymbol {
		differentTypesIncluded++
	}

	if p.MinLength < differentTypesIncluded {
		return fmt.Errorf("requested length %d is too short considering various types of characters requested, length must be at least %d",
			p.MinLength, differentTypesIncluded)
	}

	return nil
}

func (p Policy) ValidatePassword(password string) error {
	if len(password) < p.MinLength || len(password) < p.MaxLength {
		return fmt.Errorf("password lenght is %d, must be min %d and max %d", len(password), p.MinLength, p.MaxLength)
	}

	requiredAlphabets := p.getRequiredAlphabets()

	for _, alphabet := range requiredAlphabets {
		if valid := validateOverAlphabet(password, alphabet); !valid {
			return fmt.Errorf("the password doens't contain any rune from the '%s' required alphabet", alphabet)
		}
	}

	return nil
}

func validateOverAlphabet(password, alphabet string) bool {
	runes := stringToRunesMap(alphabet)

	for _, r := range password {
		if _, ok := runes[r]; ok { // the rune from password is in the alphabet
			return true
		}
	}

	return false
}

func (p Policy) getRequiredAlphabets() []string {
	result := make([]string, 0, maxRequiredAlphabets)

	if p.RequireLowercase {
		result = append(result, LowercaseLetters)
	}

	if p.RequireUppercase {
		result = append(result, UppercaseLetters)
	}

	if p.RequireDigit {
		result = append(result, Digits)
	}

	if p.RequireSymbol {
		result = append(result, Symbols)
	}

	return result
}

func (p Policy) getFullAlphabet() string {
	return LowercaseLetters + UppercaseLetters + Digits + Symbols
}

func stringToRunesMap(s string) map[rune]struct{} {
	result := make(map[rune]struct{})

	for _, b := range s {
		result[b] = struct{}{}
	}

	return result
}
