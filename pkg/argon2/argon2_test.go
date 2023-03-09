package argon2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateHash(t *testing.T) {
	password := []byte("password")

	config := DefaultConfig()

	got1, err := GenerateHash(password, config)

	if err != nil {
		t.Error(err)
		return
	}

	got2, err := GenerateHash(password, config)

	if err != nil {
		t.Error(err)
		return
	}

	if cmp.Equal(*got1, *got2) {
		t.Errorf("Values %v and %v tested equal when should be different\n", got1, got2)
		return
	}

}

func TestGenerateHashWithSalt(t *testing.T) {
	password := []byte("password")
	salt, err := GenerateSecureSalt(16)

	if err != nil {
		t.Error(err)
		return
	}

	config := DefaultConfig()

	got1, err := GenerateHashWithSalt(password, salt, config)

	if err != nil {
		t.Error(err)
		return
	}

	got2, err := GenerateHashWithSalt(password, salt, config)

	if err != nil {
		t.Error(err)
		return
	}

	if !cmp.Equal(*got1, *got2) {
		t.Errorf("Values %v and %v tested different when should be equal\n", got1, got2)
		return
	}

}

func TestDecodeHash(t *testing.T) {
	password := []byte("password")

	config := DefaultConfig()

	hash1, err := GenerateHash(password, config)

	if err != nil {
		t.Error(err)
		return
	}

	hash2, err := GenerateHash(password, config)

	if err != nil {
		t.Error(err)
		return
	}

	dechash1, err := DecodeHash(hash1.String())

	if err != nil {
		t.Error(err)
		return
	}

	dechash2, err := DecodeHash(hash2.String())

	if err != nil {
		t.Error(err)
		return
	}

	if cmp.Equal(dechash1.Hash, dechash2.Hash) {
		t.Errorf("Values %v and %v tested equal when should be different\n", dechash1.Hash, dechash2.Hash)
		return
	}

	if cmp.Equal(dechash1.Salt, dechash2.Salt) {
		t.Errorf("Values %v and %v tested equal when should be different\n", dechash1.Salt, dechash2.Salt)
		return
	}

	hash3, err := GenerateHashWithSalt(password, dechash1.Salt, config)

	if err != nil {
		t.Error(err)
		return
	}

	dechash3, err := DecodeHash(hash3.String())

	if err != nil {
		t.Error(err)
		return
	}

	if !cmp.Equal(*dechash1, *dechash3) {
		t.Errorf("Values %v and %v tested different when should be equal\n", dechash1, dechash3)
	}

}

func TestComparePasswordHash(t *testing.T) {

	password := []byte("password")
	salt, err := GenerateSecureSalt(16)

	if err != nil {
		t.Error(err)
		return
	}

	config := DefaultConfig()

	hash1, err := GenerateHash(password, config)

	if err != nil {
		t.Error(err)
		return
	}

	hash2, err := GenerateHash(password, config)

	if err != nil {
		t.Error(err)
		return
	}

	hash3, err := GenerateHashWithSalt(password, salt, config)

	if err != nil {
		t.Error(err)
		return
	}

	eq, err := ComparePasswordHash(string(password), hash1.String())

	if err != nil {
		t.Error(err)
		return
	}

	if !eq {
		t.Errorf("Values %v and %v tested different when should be equal\n", password, hash1)
		return
	}

	eq, err = ComparePasswordHash(string(password), hash2.String())

	if err != nil {
		t.Error(err)
		return
	}

	if !eq {
		t.Errorf("Values %v and %v tested different when should be equal\n", password, hash2)
		return
	}

	eq, err = ComparePasswordHash(string(password), hash3.String())

	if err != nil {
		t.Error(err)
		return
	}

	if !eq {
		t.Errorf("Values %v and %v tested different when should be equal\n", password, hash3)
		return
	}

}
