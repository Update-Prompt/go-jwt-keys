package jwtkeys

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// ErrUnknownKey means a token's kid header names none of the keys it may be signed with
var ErrUnknownKey = errors.New("token isn't signed with an accepted key")

// Sign signs the claims with EdDSA and the key, naming the key in the kid header
func (key PrivateKey) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = key.ID
	return token.SignedString(key.Key)
}

// Keyfunc returns the key a token names in its kid header, among keys, to check its
// signature with. A token naming another key, or none, is refused with ErrUnknownKey.
// More than one key lets a service accept an old and a new key while a key is rotated.
func Keyfunc(keys ...PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		keyID, _ := token.Header["kid"].(string)
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
