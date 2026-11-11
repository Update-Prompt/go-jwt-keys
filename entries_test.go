package jwtkeys

import (
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Given an entry signed by workspace-service for workspace-events
// When it is verified for that producer and stream with the key
// Then it is valid, and keeps its fields as they were
func TestSignAndVerifyEntry(t *testing.T) {
	key := newPrivateKey(t)

	signed, err := key.SignEntry("workspace-service", "workspace-events", entry())
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if err := VerifyEntry("workspace-service", "workspace-events", signed, key.Public()); err != nil {
		t.Errorf("Expected a valid entry, got %v", err)
	}
	others := maps.Clone(signed)
	delete(others, SignatureField)
	if !maps.Equal(others, entry()) || signed[SignatureField] == "" {
		t.Errorf("Expected the fields and a signature, got %v", signed)
	}
}

// Given a signed entry
// When it is changed, or verified as another producer's, another stream's, with
// another key, or without its signature
// Then it is refused with ErrBadSignature
func TestVerifyEntryRefusesChangedOrForeignEntries(t *testing.T) {
	key := newPrivateKey(t)
	signed, err := key.SignEntry("workspace-service", "workspace-events", entry())
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	changed := func(change func(map[string]string)) map[string]string {
		fields := maps.Clone(signed)
		change(fields)
		return fields
	}

	cases := map[string]struct {
		producer, stream string
		fields           map[string]string
		key              PublicKey
	}{
		"a changed field": {"workspace-service", "workspace-events",
			changed(func(fields map[string]string) { fields["api"] = "another-api" }), key.Public()},
		"an added field": {"workspace-service", "workspace-events",
			changed(func(fields map[string]string) { fields["extra"] = "1" }), key.Public()},
		"a removed field": {"workspace-service", "workspace-events",
			changed(func(fields map[string]string) { delete(fields, "at") }), key.Public()},
		"no signature": {"workspace-service", "workspace-events",
			changed(func(fields map[string]string) { delete(fields, SignatureField) }), key.Public()},
		"a value of other bytes, not UTF-8": {"workspace-service", "workspace-events",
			changed(func(fields map[string]string) { fields["api"] = "\xfe" }), key.Public()},
		"no producer to check": {"", "workspace-events", signed, key.Public()},
		"no stream to check":   {"workspace-service", "", signed, key.Public()},
		"another producer":     {"user-management-service", "workspace-events", signed, key.Public()},
		"another stream":       {"workspace-service", "user-events", signed, key.Public()},
		"another key":          {"workspace-service", "workspace-events", signed, newPrivateKey(t).Public()},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyEntry(test.producer, test.stream, test.fields, test.key); !errors.Is(err, ErrBadSignature) {
				t.Errorf("Expected ErrBadSignature, got %v", err)
			}
		})
	}
}

// Given an entry with a value that isn't UTF-8, and the same entry with other bytes there
// When the second is verified with the first's signature
// Then it is refused, so values are compared byte by byte
func TestVerifyEntryComparesBytes(t *testing.T) {
	key := newPrivateKey(t)
	signed, err := key.SignEntry("workspace-service", "workspace-events", map[string]string{"api": "\xff"})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	signed["api"] = "\xfe"

	if err := VerifyEntry("workspace-service", "workspace-events", signed, key.Public()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Expected ErrBadSignature, got %v", err)
	}
}

// Given entry signatures issued 30 seconds and 2 minutes ahead of the consumer's clock,
// and a token with the same claims but no entry typ
// When they are verified
// Then the first is valid, and the second and the token are refused
func TestVerifyEntryClockAndType(t *testing.T) {
	key := newPrivateKey(t)
	signedAt := func(ahead time.Duration, typ string) map[string]string {
		fields := entry()
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, entryClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: "workspace-service", Audience: jwt.ClaimStrings{"workspace-events"},
				IssuedAt: jwt.NewNumericDate(time.Now().Add(ahead)),
			},
			Fields: hashFields(fields),
		})
		token.Header["kid"] = key.ID
		if typ != "" {
			token.Header["typ"] = typ
		}
		signature, err := token.SignedString(key.Key)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		fields[SignatureField] = signature
		return fields
	}

	if err := VerifyEntry("workspace-service", "workspace-events", signedAt(30*time.Second, entryType),
		key.Public()); err != nil {
		t.Errorf("Expected an entry 30 seconds ahead to be valid, got %v", err)
	}
	for name, fields := range map[string]map[string]string{
		"2 minutes ahead": signedAt(2*time.Minute, entryType),
		"not an entry":    signedAt(0, ""),
	} {
		if err := VerifyEntry("workspace-service", "workspace-events", fields, key.Public()); !errors.Is(err, ErrBadSignature) {
			t.Errorf("Expected %s to be refused, got %v", name, err)
		}
	}
}

// Given a producer whose key is being rotated
// When entries signed with the old and the new key are verified with both keys
// Then both are valid
func TestVerifyEntryAcceptsEachListedKey(t *testing.T) {
	oldKey, newKey := newPrivateKey(t), newPrivateKey(t)
	for name, key := range map[string]PrivateKey{"old key": oldKey, "new key": newKey} {
		t.Run(name, func(t *testing.T) {
			signed, err := key.SignEntry("workspace-service", "workspace-events", entry())
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}
			if err := VerifyEntry("workspace-service", "workspace-events", signed,
				oldKey.Public(), newKey.Public()); err != nil {
				t.Errorf("Expected a valid entry, got %v", err)
			}
		})
	}
}

// Given an entry without a producer, one that already has a signature field, and a zero key
// When it is signed
// Then signing fails
func TestSignEntryRefusesASignatureFieldAndAnInvalidKey(t *testing.T) {
	if _, err := newPrivateKey(t).SignEntry("", "workspace-events", entry()); err == nil {
		t.Error("Expected an entry without a producer to be refused")
	}
	if _, err := newPrivateKey(t).SignEntry("workspace-service", "workspace-events",
		map[string]string{SignatureField: "x"}); err == nil {
		t.Error("Expected an entry with a signature field to be refused")
	}
	if _, err := (PrivateKey{}).SignEntry("workspace-service", "workspace-events", entry()); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// entry returns the fields of an api.deleted event
func entry() map[string]string {
	return map[string]string{
		"type": "api.deleted", "version": "1", "id": "6f1c", "workspace": "ws-1", "api": "api-1",
		"at": "2026-11-11T10:00:00Z",
	}
}
