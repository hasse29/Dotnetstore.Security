namespace Dotnetstore.Security.Models;

/// <summary>
/// A signed JWT access token.
/// </summary>
/// <param name="Value">The compact serialized JWT to send to the client.</param>
/// <param name="ExpiresAt">When the token stops being valid.</param>
public sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);
