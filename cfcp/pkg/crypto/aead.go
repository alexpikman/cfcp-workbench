package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize   // 32 bytes (256-bit)
	NonceSize = chacha20poly1305.NonceSize // 12 bytes (96-bit)
	TagSize   = chacha20poly1305.Overhead  // 16 bytes (Poly1305 authenticator)
)

var (
	ErrInvalidKeySize    = errors.New("cfcp/crypto: key must be exactly 32 bytes")
	ErrDecryptionFailed  = errors.New("cfcp/crypto: AEAD authentication failed (message altered, forged, or corrupt)")
	ErrCiphertextTooShort = errors.New("cfcp/crypto: ciphertext is shorter than Poly1305 tag size")
)

// AEADCipher wraps ChaCha20-Poly1305 encryption and decryption for CFCP.
type AEADCipher struct {
	aead cipher.AEAD
	key  [KeySize]byte
}

// NewAEADCipher initializes ChaCha20-Poly1305 with a 32-byte pre-shared key.
func NewAEADCipher(psk []byte) (*AEADCipher, error) {
	if len(psk) != KeySize {
		return nil, fmt.Errorf("%w: received %d bytes", ErrInvalidKeySize, len(psk))
	}

	c, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ChaCha20-Poly1305: %w", err)
	}

	var keyCopy [KeySize]byte
	copy(keyCopy[:], psk)

	return &AEADCipher{
		aead: c,
		key:  keyCopy,
	}, nil
}

// GenerateRandomKey creates a cryptographically secure 256-bit key.
func GenerateRandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return k, nil
}

// DeriveNonce produces a deterministic 96-bit (12-byte) nonce for a given fragment.
// Nonce structure:
// [0:8]   MessageID (64-bit BigEndian)
// [8:12]  FragmentIndex (32-bit BigEndian)
//
// This guarantees that across any given MessageID, each fragment uses a strictly
// unique nonce, satisfying ChaCha20-Poly1305 security invariants without requiring
// 12 extra nonce bytes to be transmitted over the wire.
func DeriveNonce(messageID uint64, fragmentIndex uint32) []byte {
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[0:8], messageID)
	binary.BigEndian.PutUint32(nonce[8:12], fragmentIndex)
	return nonce
}

// EncryptFragment encrypts a fragment plaintext with ChaCha20-Poly1305,
// using the derived nonce and authenticating the header AAD.
// Output: Ciphertext + 16-byte Poly1305 MAC tag.
func (c *AEADCipher) EncryptFragment(messageID uint64, fragmentIndex uint32, plaintext []byte, aad []byte) []byte {
	nonce := DeriveNonce(messageID, fragmentIndex)
	// aead.Seal appends ciphertext and tag to dst
	return c.aead.Seal(nil, nonce, plaintext, aad)
}

// DecryptFragment decrypts a fragment ciphertext and validates its Poly1305 MAC tag.
// If the payload or the AAD (header) was tampered with, this returns ErrDecryptionFailed.
func (c *AEADCipher) DecryptFragment(messageID uint64, fragmentIndex uint32, ciphertextWithTag []byte, aad []byte) ([]byte, error) {
	if len(ciphertextWithTag) < TagSize {
		return nil, ErrCiphertextTooShort
	}

	nonce := DeriveNonce(messageID, fragmentIndex)
	plaintext, err := c.aead.Open(nil, nonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ComputeMessageDigest calculates the SHA-256 integrity hash of the complete message.
func ComputeMessageDigest(data []byte) [32]byte {
	return sha256.Sum256(data)
}
