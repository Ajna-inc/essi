package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// CalculateSHA256Hash calculates SHA256 hash of input data
func CalculateSHA256Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// CalculateSHA256HashBytes calculates SHA256 hash and returns as byte slice
func CalculateSHA256HashBytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// CalculateSHA256HashString calculates SHA256 hash and returns as hex string
func CalculateSHA256HashString(data []byte) string {
	hash := sha256.Sum256(data)
	return EncodeHexString(hash[:])
}

// CalculateSHA512Hash calculates SHA512 hash of input data
func CalculateSHA512Hash(data []byte) [64]byte {
	return sha512.Sum512(data)
}

// CalculateSHA512HashBytes calculates SHA512 hash and returns as byte slice
func CalculateSHA512HashBytes(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// CalculateSHA512HashString calculates SHA512 hash and returns as hex string
func CalculateSHA512HashString(data []byte) string {
	hash := sha512.Sum512(data)
	return EncodeHexString(hash[:])
}

// CalculateSHA1Hash calculates SHA1 hash of input data
func CalculateSHA1Hash(data []byte) [20]byte {
	return sha1.Sum(data)
}

// CalculateSHA1HashBytes calculates SHA1 hash and returns as byte slice
func CalculateSHA1HashBytes(data []byte) []byte {
	hash := sha1.Sum(data)
	return hash[:]
}

// CalculateSHA1HashString calculates SHA1 hash and returns as hex string
func CalculateSHA1HashString(data []byte) string {
	hash := sha1.Sum(data)
	return EncodeHexString(hash[:])
}

// CalculateMD5Hash calculates MD5 hash of input data
func CalculateMD5Hash(data []byte) [16]byte {
	return md5.Sum(data)
}

// CalculateMD5HashBytes calculates MD5 hash and returns as byte slice
func CalculateMD5HashBytes(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

// CalculateMD5HashString calculates MD5 hash and returns as hex string
func CalculateMD5HashString(data []byte) string {
	hash := md5.Sum(data)
	return EncodeHexString(hash[:])
}

// Generic hash functions

// CalculateHash calculates hash using specified algorithm
func CalculateHash(data []byte, algorithm string) ([]byte, error) {
	var h hash.Hash

	switch algorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "sha1":
		h = sha1.New()
	case "md5":
		h = md5.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	h.Write(data)
	return h.Sum(nil), nil
}

// CalculateHashString calculates hash and returns as hex string
func CalculateHashString(data []byte, algorithm string) (string, error) {
	hashBytes, err := CalculateHash(data, algorithm)
	if err != nil {
		return "", err
	}
	return EncodeHexString(hashBytes), nil
}

// Multi-round hashing

// CalculateDoubleHash calculates hash of hash (common in blockchain)
func CalculateDoubleHash(data []byte, algorithm string) ([]byte, error) {
	firstHash, err := CalculateHash(data, algorithm)
	if err != nil {
		return nil, err
	}
	return CalculateHash(firstHash, algorithm)
}

// CalculateDoubleSHA256 calculates SHA256 of SHA256 (Bitcoin-style)
func CalculateDoubleSHA256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// CalculateDoubleSHA256Bytes calculates double SHA256 and returns as byte slice
func CalculateDoubleSHA256Bytes(data []byte) []byte {
	hash := CalculateDoubleSHA256(data)
	return hash[:]
}

// Hash validation

// ValidateHash validates that a hex string matches the hash of data
func ValidateHash(data []byte, expectedHash string, algorithm string) (bool, error) {
	calculatedHash, err := CalculateHashString(data, algorithm)
	if err != nil {
		return false, err
	}

	return CompareHexStrings(calculatedHash, expectedHash), nil
}

// ValidateSHA256Hash validates SHA256 hash
func ValidateSHA256Hash(data []byte, expectedHash string) bool {
	calculatedHash := CalculateSHA256HashString(data)
	return CompareHexStrings(calculatedHash, expectedHash)
}

// Hash from string data

// CalculateSHA256HashFromString calculates SHA256 hash from string
func CalculateSHA256HashFromString(data string) string {
	return CalculateSHA256HashString([]byte(data))
}

// CalculateSHA512HashFromString calculates SHA512 hash from string
func CalculateSHA512HashFromString(data string) string {
	return CalculateSHA512HashString([]byte(data))
}

// CalculateMD5HashFromString calculates MD5 hash from string
func CalculateMD5HashFromString(data string) string {
	return CalculateMD5HashString([]byte(data))
}

// Utility functions for common patterns

// GenerateChecksum generates a 4-byte checksum using double SHA256
func GenerateChecksum(data []byte) []byte {
	hash := CalculateDoubleSHA256(data)
	return hash[:4]
}

// VerifyChecksum verifies a 4-byte checksum
func VerifyChecksum(data []byte, checksum []byte) bool {
	if len(checksum) != 4 {
		return false
	}

	expectedChecksum := GenerateChecksum(data)
	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}
