namespace Dotnetstore.Security.Models;

/// <summary>
/// The persisted failed-attempt state for one lockout key.
/// </summary>
/// <param name="FailureCount">The number of failures in the current window.</param>
/// <param name="WindowStart">When the first failure of the current window happened.</param>
/// <param name="LockedUntil">When the lockout ends, or <see langword="null"/> if the key is not locked.</param>
/// <param name="ExpiresAt">When the state can be discarded because it no longer affects anything.</param>
public sealed record LockoutState(int FailureCount, DateTimeOffset WindowStart, DateTimeOffset? LockedUntil, DateTimeOffset ExpiresAt);

/// <summary>
/// Whether a key is locked out, as reported to the caller.
/// </summary>
/// <param name="IsLockedOut">Whether further attempts must be refused.</param>
/// <param name="RemainingAttempts">How many failures are left before lockout. Zero when locked out.</param>
/// <param name="LockedUntil">When the lockout ends, when <paramref name="IsLockedOut"/> is <see langword="true"/>.</param>
public sealed record LockoutStatus(bool IsLockedOut, int RemainingAttempts, DateTimeOffset? LockedUntil);

/// <summary>
/// Configuration for temporarily locking out a key after repeated failures.
/// </summary>
public sealed class LockoutOptions
{
    /// <summary>The number of failures within <see cref="FailureWindow"/> that triggers a lockout. Defaults to 5.</summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>How long a lockout lasts. Defaults to 15 minutes.</summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How long a failure is remembered. Failures older than this no longer count towards a lockout.
    /// Defaults to 15 minutes.
    /// </summary>
    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(15);

    internal void Validate()
    {
        if (MaxFailedAttempts < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxFailedAttempts), MaxFailedAttempts, "Must be at least 1.");
        }

        if (LockoutDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(LockoutDuration), LockoutDuration, "Must be positive.");
        }

        if (FailureWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(FailureWindow), FailureWindow, "Must be positive.");
        }
    }
}
