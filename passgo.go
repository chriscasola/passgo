package passgo

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

const iterationCount = 30000
const keySize = 32
const saltSize = 16
const maxPasswordSize = 256

// HashedPassword contains a password hash along with the salt
// and other metadata about the hash.
type HashedPassword struct {
	IterationCount int
	Salt           string
	Hash           string
	Alg            string
}

// Hash generates a HashedPassword from the given plain-text
// password.
func Hash(password string) (*HashedPassword, error) {
	// verify the password is not too long to reasonably calculate
	// a hash for (avoid DOS)
	if len(password) > maxPasswordSize {
		return nil, fmt.Errorf("Password exceeds max length of %v", maxPasswordSize)
	}

	// generate salt
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	// do the hashing
	derivedKey := pbkdf2.Key([]byte(password), salt, iterationCount, keySize, sha256.New)

	// base64 encode
	encodedKey := base64.StdEncoding.EncodeToString(derivedKey)
	encodedSalt := base64.StdEncoding.EncodeToString(salt)

	return &HashedPassword{IterationCount: iterationCount, Salt: encodedSalt, Hash: encodedKey, Alg: "sha256"}, nil
}

// Verify check if the given plain-text password hashes to the
// same value as HashedPassword
func Verify(password string, hashed *HashedPassword) bool {
	// verify the password is not too long to reasonably calculate
	// a hash for (avoid DOS)
	if len(password) > maxPasswordSize {
		return false
	}

	// base64 decode
	key, err := base64.StdEncoding.DecodeString(hashed.Hash)
	if err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(hashed.Salt)
	if err != nil {
		return false
	}

	derivedKey := pbkdf2.Key([]byte(password), salt, hashed.IterationCount, len(key), sha256.New)

	return bytes.Equal(derivedKey, key)
}
