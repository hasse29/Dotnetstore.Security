using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Checks a new password against a length-based policy following NIST SP 800-63B.
/// </summary>
public interface IPasswordPolicy
{
    /// <summary>
    /// Checks <paramref name="password"/> and reports every rule it breaks.
    /// </summary>
    /// <param name="password">The proposed password.</param>
    /// <param name="userInputs">
    /// Values specific to the user, such as username, email address and name. A password containing one of them
    /// (at least 3 characters long, ignoring case) is rejected.
    /// </param>
    /// <returns>The result. It never contains the password itself.</returns>
    PasswordPolicyResult Validate(string password, IEnumerable<string>? userInputs = null);
}

/// <summary>
/// Checks whether a password appears in known data breaches, using the Have I Been Pwned k-anonymity API.
/// Only the first five characters of the password's SHA-1 hash are sent, never the password.
/// </summary>
public interface IBreachedPasswordChecker
{
    /// <summary>
    /// Looks the password up.
    /// </summary>
    /// <param name="password">The password to check.</param>
    /// <param name="cancellationToken">A token to cancel the request.</param>
    /// <returns>
    /// <see cref="BreachStatus.Unknown"/> if the service cannot be reached, which never throws. Decide whether to
    /// accept or reject the password in that case; accepting avoids blocking sign-ups during an outage.
    /// </returns>
    Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default);
}
