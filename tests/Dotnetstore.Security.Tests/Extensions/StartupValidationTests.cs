using Dotnetstore.Security.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Tests.Extensions;

public class StartupValidationTests
{
    [Fact]
    public void InvalidArgon2Options_FailStartupValidation()
    {
        using var provider = new ServiceCollection()
            .AddSecurity(o => o.Iterations = 0)
            .BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IStartupValidator>().Validate());

        Assert.Contains("Iterations", exception.Message);
    }

    [Fact]
    public void ValidDefaults_PassStartupValidation()
    {
        using var provider = new ServiceCollection().AddSecurity().BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
    }
}
