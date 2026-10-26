namespace Dotnetstore.Security.Models;

/// <summary>
/// A way in which a password fails the policy. Map these to your own, localized messages.
/// </summary>
public enum PasswordViolation
{
    /// <summary>The password is shorter than the minimum length.</summary>
    TooShort,

    /// <summary>The password is longer than the maximum length.</summary>
    TooLong,

    /// <summary>The password is on the list of commonly used passwords.</summary>
    Common,

    /// <summary>The password is a single repeated character or a simple run such as <c>abcdefghijkl</c> or <c>123456789012</c>.</summary>
    Predictable,

    /// <summary>The password contains the user's name, email, or another supplied personal value.</summary>
    ContainsUserInput,
}

/// <summary>
/// The result of checking a password against the policy.
/// </summary>
/// <param name="Violations">Every rule the password breaks. Empty when the password is acceptable.</param>
public sealed record PasswordPolicyResult(IReadOnlyList<PasswordViolation> Violations)
{
    /// <summary>Gets a value indicating whether the password satisfies the policy.</summary>
    public bool IsValid => Violations.Count == 0;
}

/// <summary>
/// Configuration for the password policy. The defaults follow NIST SP 800-63B: length matters, composition rules
/// such as "must contain a symbol" are deliberately not used, and long passphrases are allowed.
/// </summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>The minimum length in characters. Defaults to 12.</summary>
    public int MinLength { get; set; } = 12;

    /// <summary>The maximum length in characters. Defaults to 128. Keep it generous so passphrases work.</summary>
    public int MaxLength { get; set; } = 128;

    /// <summary>Whether to reject passwords on the built-in list of common passwords. Defaults to <see langword="true"/>.</summary>
    public bool RejectCommonPasswords { get; set; } = true;

    /// <summary>Whether to reject repeated characters and simple runs. Defaults to <see langword="true"/>.</summary>
    public bool RejectPredictablePasswords { get; set; } = true;

    /// <summary>
    /// Whether to reject passwords that contain any of the user-specific values passed to the check
    /// (at least 3 characters long). Defaults to <see langword="true"/>.
    /// </summary>
    public bool RejectUserInputs { get; set; } = true;

    internal void Validate()
    {
        if (MinLength is < 8 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(MinLength), MinLength, "Must be between 8 and 256.");
        }

        if (MaxLength < MinLength || MaxLength > 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxLength),
                MaxLength,
                "Must be at least MinLength and at most 1024.");
        }
    }
}

/// <summary>
/// Whether a password appears in known data breaches.
/// </summary>
public enum BreachStatus
{
    /// <summary>The password was not found in any known breach.</summary>
    NotBreached,

    /// <summary>The password appears in known breaches and should be rejected.</summary>
    Breached,

    /// <summary>The check could not be completed, for example because the service was unreachable.</summary>
    Unknown,
}

/// <summary>
/// The result of a breached-password lookup.
/// </summary>
/// <param name="Status">Whether the password was found.</param>
/// <param name="Count">How many times the password appears in breaches, when <paramref name="Status"/> is <see cref="BreachStatus.Breached"/>.</param>
public sealed record BreachCheckResult(BreachStatus Status, long Count = 0);

/// <summary>
/// Configuration for the breached-password check against the Have I Been Pwned range API.
/// </summary>
public sealed class BreachedPasswordOptions
{
    /// <summary>The API base address. Defaults to <c>https://api.pwnedpasswords.com/</c>.</summary>
    public Uri BaseAddress { get; set; } = new("https://api.pwnedpasswords.com/");

    /// <summary>How long to wait for the service before reporting <see cref="BreachStatus.Unknown"/>. Defaults to 5 seconds.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The number of breach appearances at or above which a password counts as breached. Defaults to 1.
    /// </summary>
    public int MinimumBreachCount { get; set; } = 1;

    internal void Validate()
    {
        if (BaseAddress is null || !BaseAddress.IsAbsoluteUri)
        {
            throw new ArgumentException("BaseAddress must be an absolute URI.", nameof(BaseAddress));
        }

        if (Timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(Timeout), Timeout, "Must be positive.");
        }

        if (MinimumBreachCount < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MinimumBreachCount), MinimumBreachCount, "Must be at least 1.");
        }
    }
}
