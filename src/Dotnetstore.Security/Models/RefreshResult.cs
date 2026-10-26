namespace Dotnetstore.Security.Models;

/// <summary>
/// The outcome of exchanging a refresh token.
/// </summary>
public enum RefreshStatus
{
    /// <summary>The token was valid and has been replaced by a new one.</summary>
    Success,

    /// <summary>The token is unknown or malformed.</summary>
    Invalid,

    /// <summary>The token has expired.</summary>
    Expired,

    /// <summary>The token's family was already revoked, for example by logout or an earlier reuse.</summary>
    Revoked,

    /// <summary>
    /// A token that was already exchanged was presented again, which suggests it was stolen.
    /// The whole token family has been revoked, so the user must sign in again.
    /// </summary>
    Reused,
}

/// <summary>
/// The result of <c>IRefreshTokenService.RotateAsync</c>.
/// </summary>
/// <param name="Status">The outcome.</param>
/// <param name="Subject">The token's subject when <paramref name="Status"/> is <see cref="RefreshStatus.Success"/>; otherwise <see langword="null"/>.</param>
/// <param name="NewToken">The replacement token when <paramref name="Status"/> is <see cref="RefreshStatus.Success"/>; otherwise <see langword="null"/>.</param>
public sealed record RefreshResult(RefreshStatus Status, string? Subject = null, RefreshToken? NewToken = null)
{
    /// <summary>Gets a value indicating whether the exchange succeeded.</summary>
    public bool IsSuccess => Status == RefreshStatus.Success;
}
