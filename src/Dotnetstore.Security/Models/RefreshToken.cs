namespace Dotnetstore.Security.Models;

/// <summary>
/// An opaque refresh token. Send <see cref="Value"/> to the client and store only <see cref="Hash"/>.
/// </summary>
/// <param name="Value">The random token to give to the client. It cannot be recovered later, so do not store it.</param>
/// <param name="Hash">The value to persist and look the token up by; see <c>ITokenHandler.HashRefreshToken</c>.</param>
/// <param name="ExpiresAt">When the token stops being valid. Persist this alongside <see cref="Hash"/> and enforce it.</param>
public sealed record RefreshToken(string Value, string Hash, DateTimeOffset ExpiresAt);
