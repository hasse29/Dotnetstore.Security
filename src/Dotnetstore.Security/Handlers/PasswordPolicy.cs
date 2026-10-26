using System.Text;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

internal sealed class PasswordPolicy : IPasswordPolicy
{
    private const int MinUserInputLength = 3;

    // A small built-in list. For real protection, also use IBreachedPasswordChecker.
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password12", "password123", "passw0rd", "p@ssw0rd", "p@ssword", "letmein",
        "welcome", "welcome1", "welcome123", "admin", "admin123", "administrator", "root", "toor", "qwerty",
        "qwerty123", "qwertyuiop", "qwerty12345", "azerty", "asdfgh", "asdfghjkl", "zxcvbnm", "1q2w3e4r",
        "1q2w3e4r5t", "1qaz2wsx", "iloveyou", "monkey", "dragon", "master", "sunshine", "princess", "football",
        "baseball", "superman", "batman", "trustno1", "shadow", "michael", "jennifer", "jordan", "hunter",
        "abc123", "abc12345", "123456", "1234567", "12345678", "123456789", "1234567890", "12345678910",
        "111111", "000000", "123123", "654321", "666666", "121212", "112233", "123321", "987654321",
        "changeme", "secret", "login", "starwars", "whatever", "freedom", "access", "flower", "hello123",
        "charlie", "donald", "lovely", "ninja", "mustang", "cheese", "computer", "internet", "samsung",
        "pokemon", "minecraft", "liverpool", "arsenal", "chelsea", "summer2020", "winter2020", "spring2020",
        "password!", "password1!", "passwordpassword", "correcthorsebatterystaple", "letmein123", "iloveyou123",
        "qazwsxedc", "zaq12wsx", "q1w2e3r4", "q1w2e3r4t5", "1234qwer", "qwer1234", "asdf1234", "test1234",
        "testtest", "default", "guest", "user", "temp1234", "p4ssw0rd", "pa$$word", "pa55word", "pass1234",
    };

    private readonly PasswordPolicyOptions _options;

    public PasswordPolicy(IOptions<PasswordPolicyOptions> options)
        : this(options.Value)
    {
    }

    public PasswordPolicy(PasswordPolicyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.Validate();
        _options = new PasswordPolicyOptions
        {
            MinLength = options.MinLength,
            MaxLength = options.MaxLength,
            RejectCommonPasswords = options.RejectCommonPasswords,
            RejectPredictablePasswords = options.RejectPredictablePasswords,
            RejectUserInputs = options.RejectUserInputs,
        };
    }

    public PasswordPolicyResult Validate(string password, IEnumerable<string>? userInputs = null)
    {
        ArgumentNullException.ThrowIfNull(password);

        var violations = new List<PasswordViolation>();
        var length = password.EnumerateRunes().Count();

        if (length < _options.MinLength)
        {
            violations.Add(PasswordViolation.TooShort);
        }

        if (length > _options.MaxLength)
        {
            violations.Add(PasswordViolation.TooLong);
        }

        if (_options.RejectCommonPasswords && CommonPasswords.Contains(password.Trim()))
        {
            violations.Add(PasswordViolation.Common);
        }

        if (_options.RejectPredictablePasswords && IsPredictable(password))
        {
            violations.Add(PasswordViolation.Predictable);
        }

        if (_options.RejectUserInputs && ContainsUserInput(password, userInputs))
        {
            violations.Add(PasswordViolation.ContainsUserInput);
        }

        return new PasswordPolicyResult(violations);
    }

    private static bool ContainsUserInput(string password, IEnumerable<string>? userInputs) =>
        userInputs is not null
        && userInputs.Any(input =>
            !string.IsNullOrWhiteSpace(input)
            && input.Trim().Length >= MinUserInputLength
            && password.Contains(input.Trim(), StringComparison.OrdinalIgnoreCase));

    private static bool IsPredictable(string password)
    {
        var runes = password.EnumerateRunes().Select(r => r.Value).ToArray();
        if (runes.Length < 2)
        {
            return false;
        }

        var step = Delta(runes[0], runes[1]);
        if (step is not (0 or 1 or -1))
        {
            return false;
        }

        for (var i = 1; i < runes.Length; i++)
        {
            if (Delta(runes[i - 1], runes[i]) != step)
            {
                return false;
            }
        }

        return true;
    }

    // Digits wrap around, so 8-9-0-1 counts as a run.
    private static int Delta(int from, int to)
    {
        if (from is >= '0' and <= '9' && to is >= '0' and <= '9')
        {
            return ((to - from + 10) % 10) switch
            {
                0 => 0,
                1 => 1,
                9 => -1,
                _ => 2,
            };
        }

        return to - from;
    }
}
