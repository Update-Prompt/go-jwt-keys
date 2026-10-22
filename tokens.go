package jwtkeys

import (
	"crypto/ed25519"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// ErrUnknownKey means a token's kid header names none of the keys it may be signed with
var ErrUnknownKey = errors.New("token isn't signed with an accepted key")

// ErrNotEdDSA means a token is signed with another algorithm than EdDSA
var ErrNotEdDSA = errors.New("token isn't signed with EdDSA")

// ErrInvalidKey means a PrivateKey wasn't made by NewPrivateKey or a Parse or Load
// function, such as a zero PrivateKey from a load whose error was ignored
var ErrInvalidKey = errors.New("invalid signing key")

// Sign signs the claims with EdDSA and the key, naming the key in the kid header
func (key PrivateKey) Sign(claims jwt.Claims) (string, error) {
	if len(key.Key) != ed25519.PrivateKeySize || key.ID == "" {
		return "", ErrInvalidKey
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = key.ID
	return token.SignedString(key.Key)
}

// Keyfunc returns the key a token names in its kid header, among keys, to check its
// signature with. A token naming another key, or none, is refused with ErrUnknownKey,
// and one with another algorithm than EdDSA with ErrNotEdDSA. More than one key lets a
// service accept an old and a new key while a key is rotated. Parse with OnlyEdDSA too,
// so the parser refuses other algorithms before it asks for a key.
func Keyfunc(keys ...PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, ErrNotEdDSA
		}
		keyID, _ := token.Header["kid"].(string)
		if keyID == "" {
			return nil, ErrUnknownKey
		}
		for _, key := range keys {
			if key.ID == keyID {
				return key.Key, nil
			}
		}
		return nil, ErrUnknownKey
	}
}

// OnlyEdDSA is the parser option that refuses every algorithm but EdDSA, such as
// RS256, HS256 or none. Use it with Keyfunc.
func OnlyEdDSA() jwt.ParserOption {
	return jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()})
}
