namespace Dotnetstore.Security.Models;

/// <summary>
/// Configuration for time-based one-time passwords (RFC 6238, HMAC-SHA1), as used by authenticator apps.
/// The defaults work with Google Authenticator, Microsoft Authenticator, Authy and 1Password.
/// </summary>
public sealed class TotpOptions
{
    /// <summary>The number of digits in a code, 6 or 8. Defaults to 6, which every authenticator app supports.</summary>
    public int Digits { get; set; } = 6;

    /// <summary>How long each code is valid, in seconds. Defaults to 30.</summary>
    public int PeriodSeconds { get; set; } = 30;

    /// <summary>
    /// How many periods before and after the current one are also accepted, to tolerate clock drift and typing time.
    /// From 0 to 5. Defaults to 1.
    /// </summary>
    public int AllowedDriftSteps { get; set; } = 1;

    internal void Validate()
    {
        if (Digits is not (6 or 8))
        {
            throw new ArgumentOutOfRangeException(nameof(Digits), Digits, "Must be 6 or 8.");
        }

        if (PeriodSeconds is < 10 or > 120)
        {
            throw new ArgumentOutOfRangeException(nameof(PeriodSeconds), PeriodSeconds, "Must be between 10 and 120.");
        }

        if (AllowedDriftSteps is < 0 or > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(AllowedDriftSteps), AllowedDriftSteps, "Must be between 0 and 5.");
        }
    }
}
