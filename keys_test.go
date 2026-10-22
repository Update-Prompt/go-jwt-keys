package jwtkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Given the Ed25519 public key of RFC 8037, appendix A.2
// When its thumbprint is computed
// Then it is the one RFC 8037, appendix A.3 gives for it
func TestThumbprint(t *testing.T) {
	key, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatalf("Failed to decode the key: %v", err)
	}
	if got := Thumbprint(key); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Errorf("Expected the RFC 8037 thumbprint, got %q", got)
	}
}

// Given an Ed25519 key pair in PEM format, as openssl writes it
// When the private and the public key are parsed
// Then they are the pair's keys, and both have the public key's thumbprint as ID
func TestParseKeys(t *testing.T) {
	public, private := newKeyPair(t)

	parsedPrivate, err := ParsePrivateKey(privatePEM(t, private))
	if err != nil || !parsedPrivate.Key.Equal(private) {
		t.Fatalf("Expected the private key, got %v (error %v)", parsedPrivate.Key, err)
	}
	parsedPublic, err := ParsePublicKey(publicPEM(t, public))
	if err != nil || !parsedPublic.Key.Equal(public) {
		t.Fatalf("Expected the public key, got %v (error %v)", parsedPublic.Key, err)
	}
	if parsedPrivate.ID != Thumbprint(public) || parsedPublic.ID != parsedPrivate.ID {
		t.Errorf("Expected both IDs to be %q, got %q and %q", Thumbprint(public), parsedPrivate.ID, parsedPublic.ID)
	}
	if got := parsedPrivate.Public(); got.ID != parsedPublic.ID || !got.Key.Equal(public) {
		t.Errorf("Expected Public to return the public key with its ID")
	}
}

// Given RSA keys, content that isn't PEM, and a public key given as a private key
// When they are parsed
// Then RSA keys are refused with ErrNotEd25519, and the others with an error
func TestParseRefusesOtherKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate an RSA key: %v", err)
	}
	rsaPrivate, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to encode the RSA key: %v", err)
	}
	rsaPublic, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode the RSA key: %v", err)
	}

	if _, err := ParsePrivateKey(encodePEM("PRIVATE KEY", rsaPrivate)); !errors.Is(err, ErrNotEd25519) {
		t.Errorf("Expected ErrNotEd25519 for an RSA private key, got %v", err)
	}
	if _, err := ParsePublicKey(encodePEM("PUBLIC KEY", rsaPublic)); !errors.Is(err, ErrNotEd25519) {
		t.Errorf("Expected ErrNotEd25519 for an RSA public key, got %v", err)
	}
	if _, err := ParsePublicKey([]byte("not a key")); err == nil {
		t.Error("Expected an error for content that isn't PEM")
	}
	if _, err := ParsePrivateKey(encodePEM("PRIVATE KEY", []byte("not DER"))); err == nil {
		t.Error("Expected an error for a PEM block that isn't a key")
	}
	public, _ := newKeyPair(t)
	if _, err := ParsePrivateKey(publicPEM(t, public)); err == nil {
		t.Error("Expected an error for a public key given as the private key")
	}
}

// Given a key pair as values and as files
// When the keys are loaded
// Then a value wins over a path, and a file is read when there is no value
func TestLoadKeys(t *testing.T) {
	public, private := newKeyPair(t)
	otherPublic, otherPrivate := newKeyPair(t)
	directory := t.TempDir()
	publicPath := filepath.Join(directory, "public.pem")
	privatePath := filepath.Join(directory, "private.pem")
	writeFile(t, publicPath, publicPEM(t, otherPublic))
	writeFile(t, privatePath, privatePEM(t, otherPrivate))

	fromValue, err := LoadPublicKey(string(publicPEM(t, public)), publicPath)
	if err != nil || !fromValue.Key.Equal(public) {
		t.Errorf("Expected the public key from the value, got %v (error %v)", fromValue.Key, err)
	}
	fromFile, err := LoadPublicKey("", publicPath)
	if err != nil || !fromFile.Key.Equal(otherPublic) {
		t.Errorf("Expected the public key from the file, got %v (error %v)", fromFile.Key, err)
	}
	privateFromValue, err := LoadPrivateKey(string(privatePEM(t, private)), privatePath)
	if err != nil || !privateFromValue.Key.Equal(private) {
		t.Errorf("Expected the private key from the value, got error %v", err)
	}
	privateFromFile, err := LoadPrivateKey("", privatePath)
	if err != nil || !privateFromFile.Key.Equal(otherPrivate) {
		t.Errorf("Expected the private key from the file, got error %v", err)
	}
}

// Given no value and no path, or a path to no file
// When a key is loaded
// Then it fails with ErrKeyMissing
func TestLoadMissingKeys(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.pem")
	for name, path := range map[string]string{"no path": "", "no file": missingPath} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPublicKey("", path); !errors.Is(err, ErrKeyMissing) {
				t.Errorf("Expected ErrKeyMissing for the public key, got %v", err)
			}
			if _, err := LoadPrivateKey("", path); !errors.Is(err, ErrKeyMissing) {
				t.Errorf("Expected ErrKeyMissing for the private key, got %v", err)
			}
		})
	}
}

// Given a key file the service may not read
// When the key is loaded
// Then it fails, but not with ErrKeyMissing, so the error says what is wrong
func TestLoadUnreadableKey(t *testing.T) {
	// A directory can't be read as a file, whoever runs the test
	if _, err := LoadPublicKey("", t.TempDir()); err == nil || errors.Is(err, ErrKeyMissing) {
		t.Errorf("Expected a read error other than ErrKeyMissing, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate a key: %v", err)
	}
	return public, private
}

func privatePEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to encode the private key: %v", err)
	}
	return encodePEM("PRIVATE KEY", der)
}

func publicPEM(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("Failed to encode the public key: %v", err)
	}
	return encodePEM("PUBLIC KEY", der)
}

func encodePEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("Failed to write %s: %v", path, err)
	}
}
