package passgo

import (
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
