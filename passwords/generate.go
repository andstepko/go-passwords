package passwords

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// TODO: min-max for numbers,symbols and other characters option.
// TODO: Pass alphabets option (handle bytes/string len difference).
// TODO: Exclude characters option.

// TODO: Generate password of words (use e.g. github.com/dustinkirkland/golang-petname)
// TODO: Unit tests

type Generator struct {
	reader io.Reader
}

func NewGenerator() Generator {
	return Generator{
		reader: rand.Reader,
	}
}

func (g *Generator) SetReader(reader io.Reader) {
	g.reader = reader
}

func GenerateStrong(minLen, maxLen int) (string, error) {
	generator := NewGenerator()

	policy := NewStrongPolicy(minLen, maxLen)

	return generator.Generate(policy)
}

func MustGenerateStrong(minLen, maxLen int) string {
	result, err := GenerateStrong(minLen, maxLen)
	if err != nil {
		panic(err)
	}

	return result
}

func (g *Generator) Generate(policy Policy) (string, error) {
	if g.reader == nil {
		return "", errors.New("generator's reader is nil, please use NewGenerator constructor to get an instance of Generator")
	}

	if err := policy.Validate(); err != nil {
		return "", fmt.Errorf("invalid password Policy: %w", err)
	}

	length, err := g.pickLength(policy)
	if err != nil {
		return "", fmt.Errorf("failed to pick length for the password: %w", err)
	}

	resultBB := make([]byte, length)
	fullAlphabet := policy.getFullAlphabet()

	for i := 0; i < length; i++ {
		char, err := g.randomElement(fullAlphabet)
		if err != nil {
			return "", fmt.Errorf("failed to pick random byte from full alphabet (%s), failed at %d char: %w",
				fullAlphabet, i, err)
		}

		resultBB[i] = char
	}

	requiredAlphabets := policy.getRequiredAlphabets()
	usedPositions := make(map[int]struct{})

	for _, alphabet := range requiredAlphabets {
		char, err := g.randomElement(alphabet)
		if err != nil {
			return "", fmt.Errorf("failed to pick random byte from alphabet (%s): %w", alphabet, err)
		}

		position, err := g.randIntExcept(length, usedPositions)
		if err != nil {
			return "", fmt.Errorf("failed to generate positioin for '%s' alphabet character: %w", alphabet, err)
		}

		resultBB[position] = char
		usedPositions[position] = struct{}{}
	}

	return string(resultBB), nil
}

func (g *Generator) randomElement(s string) (byte, error) {
	randIndex, err := g.randInt(len(s))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int under %d: %w", len(s), err)
	}

	return s[randIndex], nil
}

func (g *Generator) pickLength(policy Policy) (int, error) {
	if policy.MinLength == policy.MaxLength {
		return policy.MinLength, nil
	}

	randNumRange := policy.MaxLength - policy.MinLength + 1 // +1, because both min and max inclusively.

	randNum, err := g.randInt(randNumRange)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int under %d: %w", randNumRange, err)
	}

	return policy.MinLength + randNum, nil
}

func (g *Generator) randIntExcept(maxExcl int, forbiddenNumbers map[int]struct{}) (int, error) {
	if maxExcl <= len(forbiddenNumbers) {
		return 0, fmt.Errorf("cannot generate random number between 0 and %d (exclusively) with %d forbidden numbers",
			maxExcl, len(forbiddenNumbers))
	}

	value, err := g.randInt(maxExcl)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int under %d: %w", maxExcl, err)
	}

	for isIntInSet(value, forbiddenNumbers) { // regenerate until good value is generated
		value, err = g.randInt(maxExcl)
		if err != nil {
			return 0, fmt.Errorf("failed to generate random int under %d: %w", maxExcl, err)
		}
	}

	return value, nil
}

func isIntInSet(i int, set map[int]struct{}) bool {
	_, ok := set[i]

	return ok
}

func (g *Generator) randInt(maxExcl int) (int, error) {
	randBig, err := rand.Int(g.reader, bigInt(maxExcl))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random number with the generator's reader: %w", err)
	}

	return int(randBig.Int64()), nil // maxExcl is int, so result must fit into int type.
}

func bigInt(i int) *big.Int {
	return big.NewInt(int64(i))
}
