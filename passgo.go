package passgo

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	Salt           []byte
	Hash           []byte
	Alg            string
}

// Hash generates a HashedPassword from the given plain-text
// password.
func Hash(password []byte) (*HashedPassword, error) {
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
	derivedKey := pbkdf2.Key(password, salt, iterationCount, keySize, sha256.New)

	return &HashedPassword{IterationCount: iterationCount, Salt: salt, Hash: derivedKey, Alg: "sha256"}, nil
}

// Verify check if the given plain-text password hashes to the
// same value as HashedPassword
func Verify(password []byte, hashed *HashedPassword) bool {
	// verify the password is not too long to reasonably calculate
	// a hash for (avoid DOS)
	if len(password) > maxPasswordSize {
		return false
	}

	derivedKey := pbkdf2.Key(password, hashed.Salt, hashed.IterationCount, len(hashed.Hash), sha256.New)

	return bytes.Equal(derivedKey, hashed.Hash)
}
