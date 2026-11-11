using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Tests;

internal static class StartupValidatorExtensions
{
    // IStartupValidator is obsolete from .NET 11 (SYSLIB0066); tests run on both targets.
    public static void RunStartupValidation(this IServiceProvider provider)
    {
#if NET11_0_OR_GREATER
        provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(CancellationToken.None).GetAwaiter().GetResult();
#else
        provider.GetRequiredService<IStartupValidator>().Validate();
#endif
    }
}
