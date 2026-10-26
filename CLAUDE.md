# Dotnetstore.Security -- Security Building Blocks (NuGet packages)

## Project Context

Common functions to secure an app, shipped as three NuGet packages for .NET 10. The public API is a contract: keep
implementations `internal`, expose interfaces, options and DI extensions only.

| Project | Package | Purpose |
| --- | --- | --- |
| `src/Dotnetstore.Security` | `Dotnetstore.Security` | Core handlers (hashing, encryption, tokens, 2FA, API keys, signed data, password policy, lockout) |
| `src/Dotnetstore.Security.AspNetCore` | `Dotnetstore.Security.AspNetCore` | JWT bearer wiring, security headers, login rate limiting |
| `src/Dotnetstore.Security.Tool` | `Dotnetstore.Security.Tool` | `dotnetstore-security` dotnet tool: key generation, Argon2 calibration |
| `tests/*` | -- | xUnit v3 (Microsoft.Testing.Platform) tests for core and AspNetCore |

## Tech Stack

- **.NET 10** / C# 14, nullable enabled, `TreatWarningsAsErrors`, `AnalysisLevel latest-recommended`
- **Central package management** -- versions in `Directory.Packages.props`, shared settings and package metadata in `Directory.Build.props`
- **Konscious.Security.Cryptography.Argon2** (hashing), **Microsoft.IdentityModel.JsonWebTokens** (JWT); everything else is BCL crypto
- **xUnit v3** + `Microsoft.Extensions.TimeProvider.Testing`; ASP.NET Core tests use `TestHost`
- **PublicApiAnalyzers** -- `PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt` in core and AspNetCore

## Layout (core)

```
src/Dotnetstore.Security/
  Handlers/      # I*Handler interfaces + internal implementations, stores
  Models/        # Public options and result types
  Extensions/    # ServiceCollectionExtensions: AddSecurity, AddEncryption, AddTokens, ...
  Internal/      # KeyIdentifier, SecretHasher, Base32, option validators
  KeyGenerator.cs, Argon2Calibrator.cs   # public helpers (also used by the tool)
```

Internals are visible to `Dotnetstore.Security.Tests` and `Dotnetstore.Security.AspNetCore` via `InternalsVisibleTo`.

## Conventions

- Every handler: public interface, `internal sealed` implementation, options class, `Add*` extension that registers options with `ValidateOnStart` so misconfiguration fails at startup
- Rotatable secrets (peppers, encryption keys, signing keys) carry a **key ID**; keep retired keys until no data references them
- Time comes from `TimeProvider`; HTTP from `IHttpClientFactory`; never `DateTime.Now` or `new HttpClient()`
- Public API changes: add the new signature to `PublicAPI.Unshipped.txt` (RS0016 lists it); at release, move Unshipped to Shipped. Avoid optional parameters on overloaded methods (RS0026/RS0027)
- `InMemory*Store` types are for tests and single-instance development only
- File-scoped namespaces, no regions, comments explain *why* only, XML docs on all public members
- Test projects relax some analyzers in `tests/.editorconfig` (CA1707 etc.)

## Security Library Conventions

- Constant-time comparison (`CryptographicOperations.FixedTimeEquals`) for secrets, MACs, tokens
- `RandomNumberGenerator` for all randomness; never `Random`
- Prefer BCL crypto primitives; never roll custom cryptography
- Zero sensitive buffers (`CryptographicOperations.ZeroMemory`); never log secrets
- Fail closed: invalid input or failed verification denies, never falls back
- Do not distinguish failure causes in error messages or responses (no oracles)

## Commands

```bash
dotnet build
dotnet test
dotnet pack -c Release -o ./artifacts
dotnet format --verify-no-changes

# Try the tool from source
dotnet run --project src/Dotnetstore.Security.Tool -- help
```

CI (`.github/workflows/ci.yml`) restores, builds, tests and packs on every push and pull request.

## Anti-patterns

- Exposing implementation types or breaking the public API without a major version bump
- Adding NuGet dependencies without need; each is a transitive burden on consumers
- `async void`, blocking with `.Result`/`.Wait()`, bare `catch (Exception)`
- Static mutable state; returning mutable collections from public API
- ASP.NET Core dependencies in the core package (belongs in `Dotnetstore.Security.AspNetCore`)

## MCP Tools

Use `cwm-roslyn-navigator` (`.mcp.json`) for symbol lookup, references and diagnostics before grepping.
