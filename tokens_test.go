package jwtkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Given a token signed with Sign
// When it is parsed with Keyfunc for its key and OnlyEdDSA
// Then it is valid, EdDSA, and names the key in its kid header
func TestSignAndVerify(t *testing.T) {
	key := newPrivateKey(t)

	tokenString, err := key.Sign(claims())
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	token, err := jwt.Parse(tokenString, Keyfunc(key.Public()), OnlyEdDSA())
	if err != nil {
		t.Fatalf("Expected a valid token, got %v", err)
	}
	if token.Method.Alg() != "EdDSA" || token.Header["kid"] != key.ID {
		t.Errorf("Expected EdDSA with kid %q, got %v", key.ID, token.Header)
	}
}

// Given a service that accepts an old and a new key, as while a key is rotated
// When it gets tokens signed with each
// Then both are valid
func TestKeyfuncAcceptsEachListedKey(t *testing.T) {
	oldKey, newKey := newPrivateKey(t), newPrivateKey(t)
	keys := Keyfunc(oldKey.Public(), newKey.Public())

	for name, key := range map[string]PrivateKey{"old key": oldKey, "new key": newKey} {
		t.Run(name, func(t *testing.T) {
			tokenString, err := key.Sign(claims())
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}
			if _, err := jwt.Parse(tokenString, keys, OnlyEdDSA()); err != nil {
				t.Errorf("Expected a valid token, got %v", err)
			}
		})
	}
}

// Given tokens with no kid, with another key's kid, from another key naming the
// accepted key, or signed with RS256 or none naming the accepted key
// When they are parsed with Keyfunc for the accepted key and OnlyEdDSA
// Then each is refused; a token naming no accepted key with ErrUnknownKey
func TestKeyfuncRefusesOtherTokens(t *testing.T) {
	accepted, other := newPrivateKey(t), newPrivateKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate an RSA key: %v", err)
	}

	testCases := []struct {
		name    string
		token   string
		unknown bool
	}{
		{"no kid", sign(t, jwt.SigningMethodEdDSA, accepted.Key, ""), true},
		{"another key's kid", sign(t, jwt.SigningMethodEdDSA, accepted.Key, other.ID), true},
		{"another key naming the accepted key", sign(t, jwt.SigningMethodEdDSA, other.Key, accepted.ID), false},
		{"RS256 naming the accepted key", sign(t, jwt.SigningMethodRS256, rsaKey, accepted.ID), false},
		{"none naming the accepted key", sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, accepted.ID), false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := jwt.Parse(testCase.token, Keyfunc(accepted.Public()), OnlyEdDSA())
			if err == nil {
				t.Fatal("Expected the token to be refused")
			}
			if testCase.unknown && !errors.Is(err, ErrUnknownKey) {
				t.Errorf("Expected ErrUnknownKey, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newPrivateKey(t *testing.T) PrivateKey {
	t.Helper()
	_, private := newKeyPair(t)
	return NewPrivateKey(private)
}

func claims() jwt.MapClaims {
	return jwt.MapClaims{"sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}
}

// sign signs claims() with the method and key, with keyID as the kid header unless empty
func sign(t *testing.T, method jwt.SigningMethod, key any, keyID string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims())
	if keyID != "" {
		token.Header["kid"] = keyID
	}
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	return tokenString
}
