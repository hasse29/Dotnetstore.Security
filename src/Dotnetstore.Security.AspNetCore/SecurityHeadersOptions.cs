namespace Dotnetstore.Security.AspNetCore;

/// <summary>
/// The security headers added to every response. Set a property to <see langword="null"/> to omit that header.
/// The defaults suit a JSON API; a site that serves HTML needs a looser <see cref="ContentSecurityPolicy"/>.
/// A header that the application already set on a response is never overwritten.
/// </summary>
public sealed class SecurityHeadersOptions
{
    /// <summary>Stops browsers guessing content types. Defaults to <c>nosniff</c>.</summary>
    public string? ContentTypeOptions { get; set; } = "nosniff";

    /// <summary>Stops the response being framed, which prevents clickjacking. Defaults to <c>DENY</c>.</summary>
    public string? FrameOptions { get; set; } = "DENY";

    /// <summary>Controls the <c>Referer</c> header sent on navigation. Defaults to <c>no-referrer</c>.</summary>
    public string? ReferrerPolicy { get; set; } = "no-referrer";

    /// <summary>
    /// Restricts what the response may load or run. Defaults to a policy that allows nothing and forbids framing,
    /// which is right for an API.
    /// </summary>
    public string? ContentSecurityPolicy { get; set; } = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

    /// <summary>Disables powerful browser features. Defaults to turning off camera, microphone and geolocation.</summary>
    public string? PermissionsPolicy { get; set; } = "camera=(), microphone=(), geolocation=()";

    /// <summary>Isolates the browsing context from other origins. Defaults to <c>same-origin</c>.</summary>
    public string? CrossOriginOpenerPolicy { get; set; } = "same-origin";

    /// <summary>Stops other origins embedding the response. Defaults to <c>same-origin</c>.</summary>
    public string? CrossOriginResourcePolicy { get; set; } = "same-origin";

    /// <summary>
    /// Tells browsers to use HTTPS only. Sent only on HTTPS responses, as browsers ignore it otherwise.
    /// Defaults to one year including subdomains.
    /// </summary>
    public string? StrictTransportSecurity { get; set; } = "max-age=31536000; includeSubDomains";

    /// <summary>
    /// Controls caching. Defaults to <see langword="null"/> (not set). Use <c>no-store</c> for responses that
    /// contain tokens or personal data.
    /// </summary>
    public string? CacheControl { get; set; }
}
