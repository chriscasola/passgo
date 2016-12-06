package passgo

import (
	"math/rand"
	"testing"
)

func TestPassGo(t *testing.T) {
	result, err := Hash([]byte("my secret password"))

	if err != nil {
		t.Errorf("Error creating hash: %v", err)
	}

	if !Verify([]byte("my secret password"), result) {
		t.Error("Password did not verify")
	}

	if Verify([]byte("WRONG password"), result) {
		t.Error("Password should not verify")
	}
}

func TestLimits(t *testing.T) {
	password := make([]byte, 257)

	_, err := rand.Read(password)

	if err != nil {
		t.Error("Error generating test password")
	}

	_, err = Hash(password)

	if err == nil {
		t.Error("Should prevent long password")
	}
}
