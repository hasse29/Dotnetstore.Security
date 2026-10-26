namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Time-based one-time passwords for two-factor authentication. Store each user's secret encrypted with
/// <see cref="IEncryptionHandler"/>, and also store the last accepted time step so a code cannot be used twice.
/// </summary>
public interface ITotpHandler
{
    /// <summary>
    /// Generates a new random secret to enroll a user's authenticator app.
    /// </summary>
    /// <param name="sizeInBytes">The secret length, from 16 to 64 bytes. Defaults to 20 (160 bits).</param>
    /// <returns>The secret in base32, the format authenticator apps accept.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sizeInBytes"/> is outside 16 to 64.</exception>
    string GenerateSecret(int sizeInBytes = 20);

    /// <summary>
    /// Computes the code for a secret at a point in time.
    /// </summary>
    /// <param name="secret">The base32 secret.</param>
    /// <param name="at">The time to compute the code for. Uses the current time when <see langword="null"/>.</param>
    /// <returns>The zero-padded code.</returns>
    /// <exception cref="ArgumentException"><paramref name="secret"/> is not valid base32.</exception>
    string GenerateCode(string secret, DateTimeOffset? at = null);

    /// <summary>
    /// Checks a code typed by the user.
    /// </summary>
    /// <param name="secret">The user's base32 secret.</param>
    /// <param name="code">The code typed by the user. Spaces are ignored.</param>
    /// <param name="timeStep">The time step the code belongs to when it is accepted. Store it as the user's last used step.</param>
    /// <param name="lastUsedTimeStep">
    /// The time step stored when the user last signed in successfully. Codes from that step or earlier are rejected,
    /// which prevents replaying a code that was observed or intercepted.
    /// </param>
    /// <returns><see langword="true"/> if the code is valid for the current time (within the allowed drift) and unused.</returns>
    bool Verify(string secret, string code, out long timeStep, long? lastUsedTimeStep = null);

    /// <summary>
    /// Builds the <c>otpauth://</c> URI to show as a QR code when enrolling an authenticator app.
    /// </summary>
    /// <param name="secret">The base32 secret.</param>
    /// <param name="account">The account label shown in the app, usually the user's email or username.</param>
    /// <param name="issuer">The service name shown in the app.</param>
    /// <returns>The provisioning URI. It contains the secret, so only show it to the enrolling user.</returns>
    Uri BuildProvisioningUri(string secret, string account, string issuer);
}
