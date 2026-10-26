using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Extensions;

/// <summary>
/// Dependency injection registration for Dotnetstore.Security.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the security services, including <see cref="IHashHandler"/> backed by Argon2id.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureArgon2">Optional callback to configure <see cref="Argon2Options"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddSecurity(
        this IServiceCollection services,
        Action<Argon2Options>? configureArgon2 = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configureArgon2, o => o.Validate());

        services.TryAddSingleton<IHashHandler, HashHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="IEncryptionHandler"/> backed by AES-256-GCM. At least one key must be supplied,
    /// either through <paramref name="configure"/> or by binding <see cref="EncryptionOptions"/> from configuration;
    /// otherwise the host fails at startup (or resolving the handler throws).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="EncryptionOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddEncryption(
        this IServiceCollection services,
        Action<EncryptionOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => _ = o.DecodeKeys());

        services.TryAddSingleton<IEncryptionHandler, EncryptionHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ITokenHandler"/> for creating JWT access tokens and refresh tokens. The issuer,
    /// audience, and at least one signing key must be supplied, either through <paramref name="configure"/> or by
    /// binding <see cref="TokenOptions"/> from configuration; otherwise the host fails at startup (or resolving the handler throws).
    /// Uses <see cref="TimeProvider.System"/> unless a <see cref="TimeProvider"/> is already registered.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="TokenOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddTokens(
        this IServiceCollection services,
        Action<TokenOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => TokenOptions.DisposeKeys(o.Build().Keys));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ITokenHandler, TokenHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="IRefreshTokenService"/>, which rotates refresh tokens and revokes a whole token family
    /// when a used token is presented again. Requires <see cref="AddTokens"/>.
    /// </summary>
    /// <typeparam name="TStore">
    /// Your <see cref="IRefreshTokenStore"/> implementation, registered as a singleton. If it has a shorter
    /// lifetime (for example it uses a scoped <c>DbContext</c>), register it yourself instead of using this overload's
    /// type argument and call <see cref="AddRefreshTokenRotation(IServiceCollection)"/>.
    /// </typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddRefreshTokenRotation<TStore>(this IServiceCollection services)
        where TStore : class, IRefreshTokenStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IRefreshTokenStore, TStore>();
        return services.AddRefreshTokenRotation();
    }

    /// <summary>
    /// Registers <see cref="IRefreshTokenService"/> using an <see cref="IRefreshTokenStore"/> that you register
    /// yourself, with any lifetime. The service is scoped so that it can use a scoped store. Requires <see cref="AddTokens"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddRefreshTokenRotation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<IRefreshTokenService, RefreshTokenService>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ISecretHandler"/> for generating password-reset tokens, verification codes and
    /// recovery codes, and <see cref="IApiKeyHandler"/> for creating and verifying API keys. Neither needs configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddSecrets(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ISecretHandler, SecretHandler>();
        services.TryAddSingleton<IApiKeyHandler, ApiKeyHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ISignedDataHandler"/> for signing short-lived values such as email-verification links.
    /// At least one key must be supplied, either through <paramref name="configure"/> or by binding
    /// <see cref="SignedDataOptions"/> from configuration; otherwise the host fails at startup.
    /// Uses <see cref="TimeProvider.System"/> unless a <see cref="TimeProvider"/> is already registered.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="SignedDataOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddSignedData(
        this IServiceCollection services,
        Action<SignedDataOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => _ = o.DecodeKeys());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ISignedDataHandler, SignedDataHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ITotpHandler"/> for two-factor authentication with authenticator apps.
    /// Uses <see cref="TimeProvider.System"/> unless a <see cref="TimeProvider"/> is already registered.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="TotpOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddTotp(
        this IServiceCollection services,
        Action<TotpOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => o.Validate());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ITotpHandler, TotpHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="IPasswordPolicy"/>, a length-based password check following NIST SP 800-63B.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="PasswordPolicyOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddPasswordPolicy(
        this IServiceCollection services,
        Action<PasswordPolicyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => o.Validate());
        services.TryAddSingleton<IPasswordPolicy, PasswordPolicy>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="IBreachedPasswordChecker"/>, which looks passwords up in the Have I Been Pwned
    /// database using the k-anonymity range API through <see cref="IHttpClientFactory"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="BreachedPasswordOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddBreachedPasswordChecker(
        this IServiceCollection services,
        Action<BreachedPasswordOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => o.Validate());
        services.AddHttpClient<IBreachedPasswordChecker, BreachedPasswordChecker>((provider, client) =>
        {
            client.BaseAddress = provider.GetRequiredService<IOptions<BreachedPasswordOptions>>().Value.BaseAddress;
        });
        return services;
    }

    /// <summary>
    /// Registers <see cref="ILockoutHandler"/> with an in-memory <see cref="InMemoryLockoutStore"/>, unless an
    /// <see cref="ILockoutStore"/> is already registered. Uses <see cref="TimeProvider.System"/> unless a
    /// <see cref="TimeProvider"/> is already registered.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="LockoutOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddLockout(
        this IServiceCollection services,
        Action<LockoutOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        AddValidatedOptions(services, configure, o => o.Validate());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ILockoutStore, InMemoryLockoutStore>();
        services.TryAddSingleton<ILockoutHandler, LockoutHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ILockoutHandler"/> using your own <see cref="ILockoutStore"/>, for example one backed by
    /// Redis so that every instance of an app shares the same failure counts.
    /// </summary>
    /// <typeparam name="TStore">The store implementation, registered as a singleton.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="LockoutOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddLockout<TStore>(
        this IServiceCollection services,
        Action<LockoutOptions>? configure = null)
        where TStore : class, ILockoutStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ILockoutStore, TStore>();
        return services.AddLockout(configure);
    }

    private static void AddValidatedOptions<TOptions>(
        IServiceCollection services,
        Action<TOptions>? configure,
        Action<TOptions> validate)
        where TOptions : class
    {
        var builder = services.AddOptions<TOptions>().ValidateOnStart();
        if (configure is not null)
        {
            builder.Configure(configure);
        }

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<TOptions>>(new DelegateOptionsValidator<TOptions>(validate)));
    }
}
