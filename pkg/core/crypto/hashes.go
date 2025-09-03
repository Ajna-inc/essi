package crypto

import (
	"golang.org/x/crypto/blake2b"
)

// BLAKE2BHash24 computes a BLAKE2b hash with 24-byte output
// This is used by crypto_box.go for nonce generation
func BLAKE2BHash24(data []byte) ([]byte, error) {
	hash, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	hash.Write(data)
	return hash.Sum(nil), nil
}