using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Temporarily locks out a key, such as a username or an IP address, after repeated failed attempts.
/// Check <see cref="GetStatusAsync"/> before verifying credentials, call <see cref="RecordFailureAsync"/> on a
/// failure, and <see cref="ResetAsync"/> on success.
/// </summary>
public interface ILockoutHandler
{
    /// <summary>
    /// Reports whether <paramref name="key"/> is currently locked out.
    /// </summary>
    /// <param name="key">
    /// What to lock out, prefixed by purpose and normalized, for example <c>login:ann@example.com</c> in lower case.
    /// Apply it to unknown usernames too, so the response does not reveal which accounts exist.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The current status.</returns>
    Task<LockoutStatus> GetStatusAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a failed attempt and locks the key out once the limit is reached.
    /// </summary>
    /// <param name="key">The lockout key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The status after recording the failure.</returns>
    Task<LockoutStatus> RecordFailureAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears the failures for a key, for example after a successful sign-in.
    /// </summary>
    /// <param name="key">The lockout key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the state is cleared.</returns>
    Task ResetAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>
/// Persistence for lockout state. The default in-memory implementation is per process, so with several instances
/// of an app each counts failures separately; implement this over a shared store such as Redis or a database.
/// </summary>
public interface ILockoutStore
{
    /// <summary>Gets the state for a key.</summary>
    /// <param name="key">The lockout key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The state, or <see langword="null"/> if there is none.</returns>
    ValueTask<LockoutState?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically reads the state for a key, applies <paramref name="update"/>, and stores the result, so
    /// concurrent failures are not lost. Use a transaction or compare-and-swap in a shared store.
    /// </summary>
    /// <param name="key">The lockout key.</param>
    /// <param name="update">Computes the new state from the current one (or <see langword="null"/>).</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The state that was stored.</returns>
    ValueTask<LockoutState> UpdateAsync(
        string key,
        Func<LockoutState?, LockoutState> update,
        CancellationToken cancellationToken = default);

    /// <summary>Removes the state for a key.</summary>
    /// <param name="key">The lockout key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the state is removed.</returns>
    ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default);
}
