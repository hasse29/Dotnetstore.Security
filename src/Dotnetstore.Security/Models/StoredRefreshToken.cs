namespace Dotnetstore.Security.Models;

/// <summary>
/// The persisted state of a refresh token. The token value itself is never stored, only its hash.
/// </summary>
/// <param name="Hash">The hash of the token, as produced by <c>ITokenHandler.HashRefreshToken</c>. The lookup key.</param>
/// <param name="Subject">The user or principal the token was issued to.</param>
/// <param name="FamilyId">Identifies the chain of tokens produced by rotating from one login. Revoked as a unit.</param>
/// <param name="ExpiresAt">When the token stops being valid.</param>
/// <param name="IsUsed">Whether the token has already been exchanged for a new one.</param>
/// <param name="IsRevoked">Whether the token's family has been revoked.</param>
public sealed record StoredRefreshToken(
    string Hash,
    string Subject,
    string FamilyId,
    DateTimeOffset ExpiresAt,
    bool IsUsed = false,
    bool IsRevoked = false);
