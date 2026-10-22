# go-jwt-keys

The Ed25519 keys of Update Prompt's tokens, for Go services: reading them, their key IDs, signing with them, and checking which key a token names.

- authentication-service signs every token with `EdDSA` (Ed25519) and puts the signing key's ID in the token's `kid` header.
- The ID is the key's [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint. The signer and every verifier compute it from the key, so nothing configures it.
- A verifier accepts only `EdDSA`, and only tokens whose `kid` names a key it trusts for that kind of token. Which keys sign which tokens is in [authentication-service's README](https://github.com/Update-Prompt/authentication-service#tokens-and-claims).

## Use

Verify (user-management-service, usage-service, workspace-service):

```go
userKey, err := jwtkeys.LoadPublicKey(os.Getenv("JWT_USER_PUBLIC_KEY"), os.Getenv("JWT_USER_PUBLIC_KEY_PATH"))
if err != nil {
	return err // the service doesn't start without its key
}

token, err := jwt.Parse(tokenString, jwtkeys.Keyfunc(userKey), jwtkeys.OnlyEdDSA(), jwt.WithExpirationRequired())
```

Sign (authentication-service):

```go
serviceKey, err := jwtkeys.LoadPrivateKey(os.Getenv("JWT_SERVICE_PRIVATE_KEY"), os.Getenv("JWT_SERVICE_PRIVATE_KEY_PATH"))
signed, err := serviceKey.Sign(claims) // EdDSA, kid = serviceKey.ID
```

## API

| Name | What it does |
| --- | --- |
| `LoadPublicKey(value, path)`, `LoadPrivateKey(value, path)` | Read a PEM key from `value` (such as from a secret store), or when it is empty from the file at `path`. `ErrKeyMissing` when neither gives one |
| `ParsePublicKey(pem)`, `ParsePrivateKey(pem)` | Parse a PKIX public or PKCS #8 private key, as `openssl` writes them. `ErrNotEd25519` for another kind of key, such as RSA |
| `PublicKey`, `PrivateKey` | A key and its ID. `PrivateKey.Public()` gives the public half |
| `Thumbprint(key)` | The key's RFC 7638 thumbprint, its ID |
| `PrivateKey.Sign(claims)` | A JWT signed with `EdDSA`, the key's ID in `kid` |
| `Keyfunc(keys...)` | For `jwt.Parse`: the key the token's `kid` names, among `keys`, else `ErrUnknownKey`. More than one key accepts an old and a new key while a key is rotated |
| `OnlyEdDSA()` | The `jwt.Parse` option that refuses every other `alg`, such as `RS256` or `none` |

## Keys

```bash
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -pubout -in private.pem -out public.pem
```

## Development

```bash
go test -race ./...
golangci-lint run ./...   # .golangci.yml is a copy of shared-actions' go-lint/golangci.yml
```

CI runs the tests, the lint, a `go.mod` tidy check, a secret scan and `govulncheck`. Releases are tags (`v0.1.0`, ...); services pin a tag in their `go.mod`, and Renovate updates it.
