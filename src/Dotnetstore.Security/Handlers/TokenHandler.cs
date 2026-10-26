using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Dotnetstore.Security.Handlers;

internal sealed class TokenHandler : ITokenHandler, IDisposable
{
    private const int RefreshTokenSize = 32;

    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        JwtRegisteredClaimNames.Sub,
        JwtRegisteredClaimNames.Iss,
        JwtRegisteredClaimNames.Aud,
        JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Nbf,
        JwtRegisteredClaimNames.Iat,
        JwtRegisteredClaimNames.Jti,
    };

    private readonly JsonWebTokenHandler _handler = new();
    private readonly TokenOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SigningCredentials? _signingCredentials;
    private readonly List<SecurityKey> _keys;
    private readonly TokenValidationParameters _validationParameters;

    public TokenHandler(IOptions<TokenOptions> options, TimeProvider timeProvider)
        : this(options.Value, timeProvider)
    {
    }

    public TokenHandler(TokenOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var (keys, signingKey) = options.Build();
        _keys = keys;
        _options = new TokenOptions
        {
            Issuer = options.Issuer,
            Audience = options.Audience,
            AccessTokenLifetime = options.AccessTokenLifetime,
            RefreshTokenLifetime = options.RefreshTokenLifetime,
            ClockSkew = options.ClockSkew,
            CurrentSigningKeyId = options.CurrentSigningKeyId,
            Algorithm = options.Algorithm,
        };
        _timeProvider = timeProvider;

        var algorithm = options.AlgorithmName;
        _signingCredentials = signingKey is null ? null : new SigningCredentials(signingKey, algorithm);

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys,
            ValidAlgorithms = [algorithm],
            ClockSkew = _options.ClockSkew,
            RoleClaimType = "role",
            LifetimeValidator = ValidateLifetime,
        };
    }

    internal TokenValidationParameters ValidationParameters => _validationParameters;

    public void Dispose() => TokenOptions.DisposeKeys(_keys);

    private bool ValidateLifetime(
        DateTime? notBefore,
        DateTime? expires,
        SecurityToken securityToken,
        TokenValidationParameters validationParameters)
    {
        if (expires is null)
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var skew = validationParameters.ClockSkew;

        return (notBefore is null || notBefore.Value - skew <= now) && expires.Value + skew > now;
    }

    public AccessToken CreateAccessToken(string subject, IEnumerable<Claim>? claims = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        if (_signingCredentials is null)
        {
            throw new InvalidOperationException(
                "No signing key is configured, so this handler can only validate tokens. Set CurrentSigningKeyId to a private key to create them.");
        }

        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, subject));
        identity.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")));

        foreach (var claim in claims ?? [])
        {
            if (ReservedClaims.Contains(claim.Type))
            {
                throw new ArgumentException(
                    $"The '{claim.Type}' claim is set by the handler and cannot be supplied.",
                    nameof(claims));
            }

            identity.AddClaim(claim);
        }

        var now = _timeProvider.GetUtcNow();
        var expires = now + _options.AccessTokenLifetime;

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = identity,
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = _signingCredentials,
        });

        return new AccessToken(token, expires);
    }

    public async Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        var result = await _handler.ValidateTokenAsync(token, _validationParameters).ConfigureAwait(false);
        return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
    }

    public RefreshToken CreateRefreshToken()
    {
        var value = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(RefreshTokenSize));
        return new RefreshToken(
            value,
            HashRefreshToken(value),
            _timeProvider.GetUtcNow() + _options.RefreshTokenLifetime);
    }

    public string HashRefreshToken(string refreshToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);
        return SecretHasher.Hash(refreshToken);
    }

    public bool VerifyRefreshToken(string refreshToken, string storedHash)
    {
        return SecretHasher.Verify(refreshToken, storedHash);
    }
}
