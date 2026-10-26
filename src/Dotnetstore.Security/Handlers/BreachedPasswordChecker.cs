using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

internal sealed class BreachedPasswordChecker(HttpClient httpClient, IOptions<BreachedPasswordOptions> optionsAccessor)
    : IBreachedPasswordChecker
{
    private const int PrefixLength = 5;

    private readonly BreachedPasswordOptions options = optionsAccessor.Value;

    public async Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var hash = Sha1Hex(password);
        var prefix = hash[..PrefixLength];
        var suffix = hash[PrefixLength..];

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"range/{prefix}", UriKind.Relative));
            // Padding hides the real number of matching hashes from anyone observing response sizes.
            request.Headers.Add("Add-Padding", "true");

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.Timeout);

            using var response = await httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return new BreachCheckResult(BreachStatus.Unknown);
            }

            var body = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
            return Parse(body, suffix);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            // Never fail the caller's flow because the lookup service is unavailable.
            cancellationToken.ThrowIfCancellationRequested();
            return new BreachCheckResult(BreachStatus.Unknown);
        }
    }

    private BreachCheckResult Parse(string body, string suffix)
    {
        foreach (var line in body.Split('\n'))
        {
            var separator = line.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                continue;
            }

            if (!line.AsSpan(0, separator).Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!long.TryParse(line.AsSpan(separator + 1).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var count))
            {
                return new BreachCheckResult(BreachStatus.Unknown);
            }

            return count >= options.MinimumBreachCount
                ? new BreachCheckResult(BreachStatus.Breached, count)
                : new BreachCheckResult(BreachStatus.NotBreached);
        }

        return new BreachCheckResult(BreachStatus.NotBreached);
    }

    [SuppressMessage("Security", "CA5350", Justification = "The Have I Been Pwned range API is keyed by SHA-1; it is a lookup key here, not a security control.")]
    private static string Sha1Hex(string password) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
}
