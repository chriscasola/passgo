package passgo

import (
	"strconv"
	"testing"
)

func TestPassGo(t *testing.T) {
	result, err := Hash("my secret password")

	if err != nil {
		t.Errorf("Error creating hash: %v", err)
	}

	if !Verify("my secret password", result) {
		t.Error("Password did not verify")
	}

	if Verify("WRONG password", result) {
		t.Error("Password should not verify")
	}
}

func TestLimits(t *testing.T) {
	password := ""

	for i := 0; i < 257; i++ {
		password += strconv.Itoa(i)
	}

	_, err := Hash(password)

	if err == nil {
		t.Error("Should prevent long password")
	}
}
