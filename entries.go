package jwtkeys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignatureField is the field of a stream entry that holds its signature
const SignatureField = "signature"

// entryType is the typ header of an entry's signature, so it can't pass for a token
const entryType = "entry+jwt"

// entryLeeway is how far the producer's clock may run ahead of the consumer's
const entryLeeway = time.Minute

// ErrBadSignature means a stream entry has no signature, or one that isn't valid for
// its fields, its stream or its producer
var ErrBadSignature = errors.New("the entry's signature isn't valid")

// entryClaims are the claims of an entry's signature: the producer (iss), the stream
// (aud), when it was signed (iat), and the SHA-256 of the entry's other fields
type entryClaims struct {
	jwt.RegisteredClaims
	Fields string `json:"fields"`
}

// SignEntry returns the fields of a stream entry with SignatureField added: a JWT
// signed with the key, from the producer for the stream, that holds the SHA-256 of
// the fields. The fields mustn't hold SignatureField already.
func (key PrivateKey) SignEntry(producer, stream string, fields map[string]string) (map[string]string, error) {
	if producer == "" || stream == "" {
		return nil, errors.New("an entry is signed for a producer and a stream")
	}
	if _, ok := fields[SignatureField]; ok {
		return nil, fmt.Errorf("the entry already has a %s field", SignatureField)
	}
	if len(key.Key) != ed25519.PrivateKeySize || key.ID == "" {
		return nil, ErrInvalidKey
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, entryClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   producer,
			Audience: jwt.ClaimStrings{stream},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Fields: hashFields(fields),
	})
	token.Header["kid"] = key.ID
	token.Header["typ"] = entryType
	signature, err := token.SignedString(key.Key)
	if err != nil {
		return nil, err
	}
	signed := maps.Clone(fields)
	if signed == nil {
		signed = map[string]string{}
	}
	signed[SignatureField] = signature
	return signed, nil
}

// VerifyEntry checks that a stream entry's SignatureField is signed with one of keys,
// by the producer for the stream, over exactly the entry's other fields. It returns
// an error wrapping ErrBadSignature when it isn't. More than one key accepts an old
// and a new key while the producer's key is rotated.
func VerifyEntry(producer, stream string, fields map[string]string, keys ...PublicKey) error {
	if producer == "" || stream == "" {
		// jwt skips the iss and aud checks for an empty value
		return fmt.Errorf("%w: no producer or stream to check it for", ErrBadSignature)
	}
	signature, ok := fields[SignatureField]
	if !ok {
		return fmt.Errorf("%w: it has no %s field", ErrBadSignature, SignatureField)
	}
	var claims entryClaims
	token, err := jwt.ParseWithClaims(signature, &claims, Keyfunc(keys...), OnlyEdDSA(),
		jwt.WithIssuer(producer), jwt.WithAudience(stream), jwt.WithIssuedAt(), jwt.WithLeeway(entryLeeway))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	if token.Header["typ"] != entryType {
		return fmt.Errorf("%w: it isn't an entry's signature", ErrBadSignature)
	}
	if claims.Fields != hashFields(fields) {
		return fmt.Errorf("%w: the fields were changed after signing", ErrBadSignature)
	}
	return nil
}

// hashFields returns the base64url SHA-256 of the fields but SignatureField. Each field
// is its name and then its value, each as its length in bytes (4 bytes, big-endian)
// and its bytes, in the byte order of the names. Bytes are taken as they are, so
// values that aren't UTF-8 can't run into each other.
func hashFields(fields map[string]string) string {
	hash := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if name == SignatureField {
			continue
		}
		for _, part := range []string{name, fields[name]} {
			_ = binary.Write(hash, binary.BigEndian, uint32(len(part)))
			_, _ = hash.Write([]byte(part))
		}
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
