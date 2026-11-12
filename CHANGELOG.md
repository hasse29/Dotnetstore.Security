# Changelog

## 1.1.1

- Re-release of 1.1.0 (no code changes); the 1.1.0 publish run was stuck in the GitHub Actions queue

## 1.1.0

- Packages now target both .NET 10 and .NET 11 (Microsoft package dependencies track the target framework)
- Tests and CI run against both target frameworks

## 1.0.0

- Argon2id password hashing with optional peppers, pepper IDs and rehash detection
- AES-256-GCM encryption with key rotation and associated data
- JWT access tokens (HS256, RS256, ES256) and rotating refresh tokens with reuse detection
- Secrets, API keys, signed expiring data, TOTP, password policy, Have I Been Pwned check, lockout
- ASP.NET Core integration: JWT bearer, security headers, login rate limiting
- `dotnetstore-security` tool: key generation and Argon2 calibration
