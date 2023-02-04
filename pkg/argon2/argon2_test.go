package argon2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateHash(t *testing.T) {
	password := "password"

	config := DefaultConfig()

	got1, err := GenerateHash([]byte(password), config)

	if err != nil {
		t.Error(err)
		return
	}

	got2, err := GenerateHash([]byte(password), config)

	if err != nil {
		t.Error(err)
		return
	}

	if cmp.Equal(got1, got2) {
		t.Errorf("Values %v and %v tested equal when should be different\n", got1, got2)
		return
	}

}
