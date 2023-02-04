package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Version uint8

const (
	Argon2i Version = iota
	Argon2id
)

const CurrentVersion = argon2.Version

type Config struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
	Type       Version
}

type Argon2Hash struct {
	Salt   []byte
	Hash   []byte
	Config *Config
}

var (
	ErrInvalidType    = errors.New("invalid argon2 type")
	ErrInvalidHash    = errors.New("invalid hash")
	ErrInvalidVersion = errors.New("invalid version")
	ErrInvalidParams  = errors.New("invalid parameters")
)

func GenerateHash(password []byte, config *Config) (*Argon2Hash, error) {

	if config == nil {
		return nil, ErrInvalidParams
	}

	salt, err := GenerateSecureSalt(config.SaltLength)

	if err != nil {
		return nil, err
	}

	return GenerateHashWithSalt(password, salt, config)
}

func GenerateHashWithSalt(password, salt []byte, config *Config) (*Argon2Hash, error) {

	if config == nil {
		return nil, ErrInvalidParams
	}

	pepper := []byte(os.Getenv("SECRET_PEPPER"))

	password = append(password, pepper...)

	var hash []byte

	if config.Type == Argon2id {
		hash = argon2.IDKey(password, salt, config.Time, config.Memory, config.Threads, config.KeyLength)
	} else if config.Type == Argon2i {
		hash = argon2.Key(password, salt, config.Time, config.Memory, config.Threads, config.KeyLength)
	}

	return &Argon2Hash{
		Salt:   salt,
		Hash:   hash,
		Config: config,
	}, nil
}

func DecodeHash(hashStr string) (*Argon2Hash, error) {

	vals := strings.Split(hashStr, "$")

	if len(vals) != 5 {
		return nil, ErrInvalidHash
	}

	var argonType Version

	if vals[0] == "argon2i" {
		argonType = Argon2i
	} else if vals[0] == "argon2id" {
		argonType = Argon2id
	} else {
		return nil, ErrInvalidType
	}

	var version int

	_, err := fmt.Sscanf(vals[1], "v=%d", &version)

	if err != nil {
		return nil, err
	}

	if version != argon2.Version {
		return nil, ErrInvalidVersion
	}

	config := &Config{}

	_, err = fmt.Sscanf(vals[2], "m=%d,t=%d,p=%d", &config.Memory, &config.Time, &config.Threads)

	if err != nil {
		return nil, err
	}

	config.Type = argonType

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[3])

	config.SaltLength = uint32(len(salt))

	if err != nil {
		return nil, err
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])

	if err != nil {
		return nil, err
	}

	config.KeyLength = uint32(len(hash))

	return &Argon2Hash{
		Hash:   hash,
		Salt:   salt,
		Config: config,
	}, nil
}

func ComparePasswordHash(password, hash string) (bool, error) {

	originalHash, err := DecodeHash(hash)

	if err != nil {
		return false, err
	}

	newHash, err := GenerateHashWithSalt([]byte(password), originalHash.Salt, originalHash.Config)

	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(newHash.Hash, originalHash.Hash) == 1, nil
}

func GenerateSecureSalt(length uint32) ([]byte, error) {
	b := make([]byte, length)

	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (v Version) String() string {
	if v == Argon2id {
		return "argon2id"
	} else if v == Argon2i {
		return "argon2i"
	}
	return ""
}

func (hash *Argon2Hash) String() (encodedHash string) {

	b64Hash := base64.RawStdEncoding.EncodeToString(hash.Hash)
	b64Salt := base64.RawStdEncoding.EncodeToString(hash.Salt)

	encodedHash = fmt.Sprintf(
		"%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		hash.Config.Type.String(),
		argon2.Version,
		hash.Config.Memory,
		hash.Config.Time,
		hash.Config.Threads,
		b64Salt,
		b64Hash,
	)

	return
}

func DefaultConfig() *Config {
	return &Config{
		Memory:     6 * 1024,
		Time:       3,
		Threads:    2,
		SaltLength: 16,
		KeyLength:  32,
		Type:       Argon2id,
	}
}
