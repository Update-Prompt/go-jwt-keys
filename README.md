# go-jwt-keys

The Ed25519 keys of Update Prompt's tokens, for Go services: reading them, their key IDs, signing with them, and checking which key a token names.

- authentication-service signs every token with `EdDSA` (Ed25519) and puts the signing key's ID in the token's `kid` header.
- The ID is the key's [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint. The signer and every verifier compute it from the key, so nothing configures it.
- A verifier accepts only `EdDSA`, and only tokens whose `kid` names a key it trusts for that kind of token. Which keys sign which tokens is in [authentication-service's README](https://github.com/Update-Prompt/authentication-service#tokens-and-claims).

## Use

Verify (user-management-service, usage-service, workspace-service):

```go
// The value, or else the path with the service's own default
userKey, err := jwtkeys.LoadPublicKey(config.JWTUserPublicKey, config.JWTUserPublicKeyPath)
if err != nil {
	return err // the service doesn't start without its key
}

token, err := jwt.Parse(tokenString, jwtkeys.Keyfunc(userKey), jwtkeys.OnlyEdDSA(), jwt.WithExpirationRequired())
```

Sign (authentication-service):

```go
serviceKey, err := jwtkeys.LoadPrivateKey(config.JWTServicePrivateKey, config.JWTServicePrivateKeyPath)
if err != nil {
	return err // load at start, so a missing key stops the service
}
signed, err := serviceKey.Sign(claims) // EdDSA, kid = serviceKey.ID
```

## API

| Name | What it does |
| --- | --- |
| `LoadPublicKey(value, path)`, `LoadPrivateKey(value, path)` | Read a PEM key from `value` (such as from a secret store), or when it is empty from the file at `path`. `ErrKeyMissing` when there is no value and no file at the path; another error when the file can't be read |
| `ParsePublicKey(pem)`, `ParsePrivateKey(pem)` | Parse a `PUBLIC KEY` (PKIX) or `PRIVATE KEY` (PKCS #8) block, as `openssl` writes them. `ErrNotEd25519` for another kind of key, such as RSA |
| `PublicKey`, `PrivateKey` | A key and its ID. `PrivateKey.Public()` gives the public half |
| `Thumbprint(key)` | The key's RFC 7638 thumbprint, its ID |
| `PrivateKey.Sign(claims)` | A JWT signed with `EdDSA`, the key's ID in `kid`. `ErrInvalidKey` for a key not made by this package, such as a zero `PrivateKey` |
| `Keyfunc(keys...)` | For `jwt.Parse`: the key the token's `kid` names, among `keys`, else `ErrUnknownKey` (also for no `kid`). `ErrNotEdDSA` for another algorithm. More than one key accepts an old and a new key while a key is rotated |
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
