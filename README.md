# Dotnetstore.Security

[![CI](https://github.com/hasse29/Dotnetstore.Security/actions/workflows/ci.yml/badge.svg)](https://github.com/hasse29/Dotnetstore.Security/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Dotnetstore.Security.svg)](https://www.nuget.org/packages/Dotnetstore.Security)
[![NuGet downloads](https://img.shields.io/nuget/dt/Dotnetstore.Security.svg)](https://www.nuget.org/packages/Dotnetstore.Security)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4.svg)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Common functions to secure an app, as small, well-tested building blocks for .NET 10.

| Package | What it is |
| --- | --- |
| `Dotnetstore.Security` | Hashing, encryption, JWT and refresh tokens, 2FA, API keys, signed links, password checks, lockout |
| `Dotnetstore.Security.AspNetCore` | JWT bearer authentication, security headers and login rate limiting for ASP.NET Core |
| `Dotnetstore.Security.Tool` | `dotnet tool` that generates keys and calibrates Argon2 |

Every handler is registered with dependency injection, configured through an options class (set in code or bound
from configuration), and **validated when the host starts**, so a missing key fails the deploy, not the first login.
Secrets that can rotate (peppers, encryption keys, signing keys) carry a **key ID**, so you can introduce a new key
while old data keeps working.

## Quick start

```csharp
services.AddSecurity();                    // password hashing (Argon2id)
services.AddEncryption(o => { ... });      // AES-256-GCM
services.AddTokens(o => { ... });          // JWT access tokens + refresh tokens
services.AddRefreshTokenRotation<MyStore>();
services.AddSecrets();                     // reset tokens, codes, recovery codes, API keys
services.AddSignedData(o => { ... });      // expiring signed links
services.AddTotp();                        // authenticator-app 2FA
services.AddPasswordPolicy();              // NIST-style rules
services.AddBreachedPasswordChecker();     // Have I Been Pwned (k-anonymity)
services.AddLockout();                     // lock out after repeated failures
```

Generate the keys and secrets once and keep them in a secret store, never in source control:

```bash
dotnet tool install -g Dotnetstore.Security.Tool
dotnetstore-security secret            # HS256 signing key / signed-data key
dotnetstore-security encryption-key
dotnetstore-security pepper
dotnetstore-security ec                # ES256 key pair (or: rsa)
dotnetstore-security calibrate --target-ms 250   # Argon2 settings for this hardware
```

## Password hashing: `IHashHandler`

Argon2id (RFC 9106 defaults: 64 MiB, 3 passes, 4 lanes). Hashes are PHC strings
(`$argon2id$v=19$m=65536,t=3,p=4$salt$hash`), so verification uses the parameters stored in the hash and you can raise
the cost later.

```csharp
var hash = hasher.Hash(password);              // store this
if (hasher.Verify(password, storedHash))
{
    if (hasher.NeedsRehash(storedHash))        // cost raised, or pepper rotated
        user.PasswordHash = hasher.Hash(password);
}
```

Optional **peppers** (a server-side secret kept out of the database) are mixed in as Argon2's secret input and
identified by ID in the hash (`...,keyid=v1$...`):

```csharp
services.AddSecurity(o =>
{
    o.Peppers["v2"] = "<base64, 16+ bytes>";
    o.Peppers["v1"] = "<old pepper, still needed to verify old hashes>";
    o.CurrentPepperId = "v2";
});
```

`ReadOnlySpan<char>` overloads let you hash a password without ever creating a string.

## Encryption: `IEncryptionHandler`

AES-256-GCM with a random nonce per call. Output is `dse1.{keyId}.{base64url}`. Strings and bytes share one format.

```csharp
var payload = crypto.Encrypt("secret", associatedData: userId);   // bind it to a record
var text = crypto.Decrypt(payload, associatedData: userId);       // throws CryptographicException on any failure
crypto.TryDecrypt(payload, out var plain, userId);
crypto.NeedsReEncryption(payload);                                // encrypted with a retired key
```

Keep retired keys in `EncryptionOptions.Keys` until no payload references them. Random 96-bit nonces are safe up to
about 2³² encryptions per key, so rotate well before that.

## Tokens: `ITokenHandler`, `IRefreshTokenService`

JWT access tokens signed with **HS256**, **RS256** or **ES256** (`TokenOptions.Algorithm`). Validation pins the
algorithm, so `alg: none` and algorithm-confusion tokens are rejected.

```csharp
services.AddTokens(o =>
{
    o.Issuer = "https://auth.example.com";
    o.Audience = "api";
    o.Algorithm = SigningAlgorithm.ES256;
    o.SigningKeys["k1"] = privateKeyPem;       // issuer: private key
    o.CurrentSigningKeyId = "k1";              // validate-only services: public key, no current id
});

var access = tokens.CreateAccessToken("user-1", [new Claim("role", "admin")]);
ClaimsPrincipal? principal = await tokens.ValidateAccessTokenAsync(access.Value);
```

**Refresh tokens** are random, opaque and stored hashed. `IRefreshTokenService` rotates them and detects theft: each
token works once, and presenting a used token revokes the whole chain.

```csharp
var refresh = await refreshService.IssueAsync("user-1");           // at login
var result = await refreshService.RotateAsync(presentedToken);     // at refresh
if (!result.IsSuccess) return Unauthorized();                      // same answer for every failure
var access = tokens.CreateAccessToken(result.Subject!);
```

Implement `IRefreshTokenStore` over your database (`TryMarkUsedAsync` must be an atomic conditional update).
`InMemoryRefreshTokenStore` is for tests and development only.

## ASP.NET Core: `Dotnetstore.Security.AspNetCore`

```csharp
builder.Services.AddTokens(o => { ... });
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddSecurityJwtBearer();
builder.Services.AddLoginRateLimiting(o => o.PermitLimit = 10);

app.UseSecurityHeaders();      // nosniff, frame deny, CSP, referrer, HSTS on HTTPS...
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", Login).RequireRateLimiting(RateLimitingExtensions.LoginPolicy);
```

`AddSecurityJwtBearer` validates exactly like `ITokenHandler`, claims keep their JWT names (`sub`, `role`), and a
service that only validates tokens needs just the public key. The default CSP suits a JSON API; loosen it with
`AddSecurityHeaders(o => o.ContentSecurityPolicy = "...")` for sites that serve HTML.

## Smaller building blocks

| Need | Use |
| --- | --- |
| Password-reset or email-verification token, stored hashed | `ISecretHandler.Generate()` |
| SMS or email numeric code | `ISecretHandler.GenerateCode(6)` |
| 2FA backup codes | `ISecretHandler.GenerateRecoveryCodes()` |
| API keys (`live.id.secret`, lookup by id, constant-time verify) | `IApiKeyHandler` |
| Expiring, tamper-proof link payload bound to a purpose | `ISignedDataHandler.Sign(payload, "email-verification")` |
| Authenticator-app 2FA (RFC 6238), replay protection | `ITotpHandler` |
| Length-based password rules (NIST SP 800-63B) | `IPasswordPolicy` |
| "Has this password leaked?" without sending it | `IBreachedPasswordChecker` |
| Lock an account or IP after repeated failures | `ILockoutHandler` |

Store TOTP secrets encrypted with `IEncryptionHandler`, and apply `ILockoutHandler` to unknown usernames too, so
responses do not reveal which accounts exist. The in-memory lockout store is per process: with several instances,
implement `ILockoutStore` over a shared store.

## Building

```bash
dotnet build
dotnet test
dotnet pack -c Release
```

## License

MIT
