using System.Net;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Tests.Handlers;

public class PasswordPolicyTests
{
    private static PasswordPolicy CreatePolicy(Action<PasswordPolicyOptions>? configure = null)
    {
        var options = new PasswordPolicyOptions();
        configure?.Invoke(options);
        return new PasswordPolicy(options);
    }

    [Fact]
    public void LongUnpredictablePassphrase_IsValid()
    {
        var result = CreatePolicy().Validate("correct horse battery staple 42");

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
    }

    [Fact]
    public void NoCompositionRules_AreApplied()
    {
        Assert.True(CreatePolicy().Validate("onlylowercaseletters").IsValid);
    }

    [Fact]
    public void TooShortAndTooLong_AreReported()
    {
        var policy = CreatePolicy(o => o.MaxLength = 20);

        Assert.Contains(PasswordViolation.TooShort, policy.Validate("short1!").Violations);
        Assert.Contains(PasswordViolation.TooLong, policy.Validate(new string('x', 5) + "yzabcdefghijklmnopqrstu").Violations);
    }

    [Fact]
    public void LengthCountsCharactersNotUtf16Units()
    {
        var policy = CreatePolicy(o => o.MinLength = 8);

        // Eight emoji are 16 UTF-16 units but eight characters.
        Assert.Contains(PasswordViolation.TooShort, policy.Validate(string.Concat(Enumerable.Repeat("😀", 7))).Violations);
        Assert.DoesNotContain(PasswordViolation.TooShort, policy.Validate(string.Concat(Enumerable.Repeat("😀", 8))).Violations);
    }

    [Theory]
    [InlineData("password123")]
    [InlineData("PASSWORD123")]
    [InlineData("qwertyuiop")]
    [InlineData("iloveyou")]
    public void CommonPasswords_AreRejectedCaseInsensitively(string password)
    {
        var policy = CreatePolicy(o => o.MinLength = 8);

        Assert.Contains(PasswordViolation.Common, policy.Validate(password).Violations);
    }

    [Theory]
    [InlineData("aaaaaaaaaaaa")]
    [InlineData("123456789012")]
    [InlineData("abcdefghijkl")]
    [InlineData("987654321098")]
    public void PredictablePasswords_AreRejected(string password)
    {
        Assert.Contains(PasswordViolation.Predictable, CreatePolicy().Validate(password).Violations);
    }

    [Fact]
    public void UserInputs_AreRejectedWhenContained()
    {
        var policy = CreatePolicy();
        string[] inputs = ["ann.lee@example.com", "Ann", "Lee"];

        Assert.Contains(PasswordViolation.ContainsUserInput, policy.Validate("my-ANN-secret-phrase", inputs).Violations);
        Assert.Contains(PasswordViolation.ContainsUserInput, policy.Validate("xx-ann.lee@example.com-xx", inputs).Violations);
        Assert.DoesNotContain(PasswordViolation.ContainsUserInput, policy.Validate("completely unrelated phrase", inputs).Violations);
    }

    [Fact]
    public void ShortOrBlankUserInputs_AreIgnored()
    {
        var policy = CreatePolicy();

        Assert.True(policy.Validate("my-secret-phrase-here", ["my", "  ", ""]).IsValid);
    }

    [Fact]
    public void Rules_CanBeDisabled()
    {
        var policy = CreatePolicy(o =>
        {
            o.RejectCommonPasswords = false;
            o.RejectPredictablePasswords = false;
            o.RejectUserInputs = false;
        });

        Assert.True(policy.Validate("aaaaaaaaaaaaaaaa", ["aaa"]).IsValid);
    }

    [Fact]
    public void MultipleViolations_AreAllReported()
    {
        var result = CreatePolicy().Validate("aaa");

        Assert.Contains(PasswordViolation.TooShort, result.Violations);
        Assert.Contains(PasswordViolation.Predictable, result.Violations);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void InvalidOptions_Throw()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CreatePolicy(o => o.MinLength = 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => CreatePolicy(o => o.MaxLength = 5));
        Assert.Throws<ArgumentNullException>(() => CreatePolicy().Validate(null!));
    }

    [Fact]
    public void AddPasswordPolicy_ResolvesPolicyAndValidatesAtStartup()
    {
        using var provider = new ServiceCollection().AddPasswordPolicy(o => o.MinLength = 16).BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
        Assert.Contains(
            PasswordViolation.TooShort,
            provider.GetRequiredService<IPasswordPolicy>().Validate("fifteen chars!!").Violations);

        using var broken = new ServiceCollection().AddPasswordPolicy(o => o.MinLength = 1).BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => broken.GetRequiredService<IStartupValidator>().Validate());
    }
}

public class BreachedPasswordCheckerTests
{
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    private const string PasswordPrefix = "5BAA6";
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }

    private static (BreachedPasswordChecker Checker, StubHandler Handler) Create(
        Func<HttpRequestMessage, HttpResponseMessage> respond,
        Action<BreachedPasswordOptions>? configure = null)
    {
        var options = new BreachedPasswordOptions();
        configure?.Invoke(options);
        var handler = new StubHandler(respond);
        var client = new HttpClient(handler) { BaseAddress = options.BaseAddress };
        return (new BreachedPasswordChecker(client, Options.Create(options)), handler);
    }

    private static HttpResponseMessage Ok(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };

    [Fact]
    public async Task BreachedPassword_IsReportedWithCount_AndOnlyThePrefixIsSent()
    {
        var (checker, handler) = Create(_ => Ok($"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{PasswordSuffix}:10434004\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:1"));

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.Breached, result.Status);
        Assert.Equal(10434004, result.Count);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"/range/{PasswordPrefix}", request.RequestUri!.AbsolutePath);
        Assert.DoesNotContain(PasswordSuffix, request.RequestUri.PathAndQuery, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", request.RequestUri.PathAndQuery, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("true", request.Headers.GetValues("Add-Padding"));
    }

    [Fact]
    public async Task AbsentPassword_IsNotBreached()
    {
        var (checker, _) = Create(_ => Ok("0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:1"));

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.NotBreached, result.Status);
    }

    [Fact]
    public async Task PaddingEntriesWithZeroCount_AreIgnored()
    {
        var (checker, _) = Create(_ => Ok($"{PasswordSuffix}:0\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0"));

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.NotBreached, result.Status);
    }

    [Fact]
    public async Task MinimumBreachCount_RaisesTheThreshold()
    {
        var (checker, _) = Create(_ => Ok($"{PasswordSuffix}:2"), o => o.MinimumBreachCount = 5);

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.NotBreached, result.Status);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task ServerErrors_ReportUnknownInsteadOfThrowing(HttpStatusCode status)
    {
        var (checker, _) = Create(_ => new HttpResponseMessage(status));

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.Unknown, result.Status);
    }

    [Fact]
    public async Task NetworkFailure_ReportsUnknown()
    {
        var (checker, _) = Create(_ => throw new HttpRequestException("down"));

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.Unknown, result.Status);
    }

    [Fact]
    public async Task MalformedCount_ReportsUnknown()
    {
        var (checker, _) = Create(_ => Ok($"{PasswordSuffix}:lots"));

        var result = await checker.CheckAsync("password", TestContext.Current.CancellationToken);

        Assert.Equal(BreachStatus.Unknown, result.Status);
    }

    [Fact]
    public async Task CallerCancellation_StillPropagates()
    {
        var (checker, _) = Create(_ => throw new OperationCanceledException());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => checker.CheckAsync("password", cts.Token));
    }

    [Fact]
    public async Task EmptyPassword_Throws()
    {
        var (checker, _) = Create(_ => Ok(""));

        await Assert.ThrowsAsync<ArgumentException>(() => checker.CheckAsync("", TestContext.Current.CancellationToken));
    }

    [Fact]
    public void InvalidOptions_FailStartupValidation()
    {
        using var provider = new ServiceCollection()
            .AddBreachedPasswordChecker(o => o.MinimumBreachCount = 0)
            .BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
    }

    [Fact]
    public void AddBreachedPasswordChecker_ResolvesTypedClientWithConfiguredBaseAddress()
    {
        using var provider = new ServiceCollection()
            .AddBreachedPasswordChecker(o => o.BaseAddress = new Uri("https://pwned.example.test/"))
            .BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<IBreachedPasswordChecker>());
    }
}
