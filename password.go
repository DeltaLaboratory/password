package password

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// argon2id params
var (
	// Time is the number of iterations
	Time uint32 = 1
	// Memory is the memory usage in KiB
	Memory uint32 = 1024 * 64
	// Threads is the number of threads to calculate the hash
	Threads uint8 = 2
	// SaltLength is the length of the salt
	SaltLength uint32 = 16
	// KeyLength is the length of the hashed key
	KeyLength uint32 = 32
)

// Generate generates a new hashed password
func Generate(password []byte, s ...[]byte) ([]byte, error) {
	var salt []byte

	if len(s) > 0 {
		if len(s[0]) != int(SaltLength) {
			return nil, fmt.Errorf("invalid salt: length must be %d, got %d", SaltLength, len(s[0]))
		}
		salt = s[0]
	} else {
		salt = make([]byte, SaltLength)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate new salt: %w", err)
		}
	}
	return append(salt, argon2.IDKey(password, salt, Time, Memory, Threads, KeyLength)...), nil
}

// Verify verifies a password against a hash
func Verify(password, hash []byte) (bool, error) {
	if len(hash) != int(SaltLength+KeyLength) {
		return false, fmt.Errorf("invalid hash: length must be %d, got %d", SaltLength+KeyLength, len(hash))
	}
	if hmac.Equal(argon2.IDKey(password, hash[:SaltLength], Time, Memory, Threads, KeyLength), hash[SaltLength:]) {
		return true, nil
	}
	return false, nil
}
