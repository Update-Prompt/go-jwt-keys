// Package jwtkeys holds the Ed25519 keys of Update Prompt's tokens: reading them, their
// key IDs, signing with them and checking which key a token names.
//
// The auth services sign every token with EdDSA (Ed25519) and put the signing key's ID
// in the token's kid header. The ID is the key's RFC 7638 JWK thumbprint, so the signer
// and every verifying service compute it from the key: nothing configures it.
package jwtkeys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrKeyMissing means a key is set neither as a value nor as a readable file
var ErrKeyMissing = errors.New("key is missing")

// ErrNotEd25519 means a key is a valid key of another kind, such as RSA
var ErrNotEd25519 = errors.New("key isn't an Ed25519 key")

// PublicKey is an Ed25519 public key and its ID
type PublicKey struct {
	Key ed25519.PublicKey
	ID  string
}

// PrivateKey is an Ed25519 private key and the ID of its public key
type PrivateKey struct {
	Key ed25519.PrivateKey
	ID  string
}

// NewPublicKey returns the key with its ID
func NewPublicKey(key ed25519.PublicKey) PublicKey {
	return PublicKey{Key: key, ID: Thumbprint(key)}
}

// NewPrivateKey returns the key with the ID of its public key
func NewPrivateKey(key ed25519.PrivateKey) PrivateKey {
	return PrivateKey{Key: key, ID: Thumbprint(key.Public().(ed25519.PublicKey))}
}

// Public returns the key's public half, with the same ID
func (key PrivateKey) Public() PublicKey {
	return PublicKey{Key: key.Key.Public().(ed25519.PublicKey), ID: key.ID}
}

// Thumbprint returns the key's RFC 7638 JWK thumbprint: base64url (no padding) of the
// SHA-256 of the key's JWK with only its required members, in lexicographic order
func Thumbprint(key ed25519.PublicKey) string {
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParsePublicKey parses an Ed25519 public key in PEM format (PKIX, "PUBLIC KEY")
func ParsePublicKey(pemContent []byte) (PublicKey, error) {
	der, err := decodePEM(pemContent, "PUBLIC KEY")
	if err != nil {
		return PublicKey{}, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed to parse the public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return PublicKey{}, ErrNotEd25519
	}
	return NewPublicKey(key), nil
}

// ParsePrivateKey parses an Ed25519 private key in PEM format (PKCS #8, "PRIVATE KEY"),
// as `openssl genpkey -algorithm ed25519` writes it
func ParsePrivateKey(pemContent []byte) (PrivateKey, error) {
	der, err := decodePEM(pemContent, "PRIVATE KEY")
	if err != nil {
		return PrivateKey{}, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("failed to parse the private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return PrivateKey{}, ErrNotEd25519
	}
	return NewPrivateKey(key), nil
}

// LoadPublicKey reads a public key from value, the PEM itself such as from a secret
// store, or when value is empty from the file at path
func LoadPublicKey(value, path string) (PublicKey, error) {
	content, err := read(value, path)
	if err != nil {
		return PublicKey{}, err
	}
	return ParsePublicKey(content)
}

// LoadPrivateKey reads a private key from value, or when value is empty from the file
// at path
func LoadPrivateKey(value, path string) (PrivateKey, error) {
	content, err := read(value, path)
	if err != nil {
		return PrivateKey{}, err
	}
	return ParsePrivateKey(content)
}

func read(value, path string) ([]byte, error) {
	if value != "" {
		return []byte(value), nil
	}
	if path == "" {
		return nil, ErrKeyMissing
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrKeyMissing, err)
	}
	if err != nil {
		// Such as a file the service's user may not read
		return nil, fmt.Errorf("failed to read the key: %w", err)
	}
	return content, nil
}

// decodePEM returns the DER of the first PEM block, which must be of the type
func decodePEM(content []byte, blockType string) ([]byte, error) {
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("key isn't in PEM format")
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("expected a %s PEM block, got %s", blockType, block.Type)
	}
	return block.Bytes, nil
}
