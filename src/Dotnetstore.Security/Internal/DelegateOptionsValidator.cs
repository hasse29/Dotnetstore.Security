using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Internal;

/// <summary>
/// Adapts an options type's own validation, which throws <see cref="ArgumentException"/>, to
/// <see cref="IValidateOptions{TOptions}"/> so misconfiguration is reported when the host starts.
/// </summary>
internal sealed class DelegateOptionsValidator<TOptions>(Action<TOptions> validate) : IValidateOptions<TOptions>
    where TOptions : class
{
    public ValidateOptionsResult Validate(string? name, TOptions options)
    {
        try
        {
            validate(options);
            return ValidateOptionsResult.Success;
        }
        catch (ArgumentException ex)
        {
            return ValidateOptionsResult.Fail(ex.Message);
        }
    }
}
