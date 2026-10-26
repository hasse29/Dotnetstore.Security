using System.Globalization;

namespace Dotnetstore.Security.Tool;

/// <summary>
/// The command-line interface, separated from <c>Program</c> so that it can be tested.
/// </summary>
internal static class Cli
{
    private const string Usage = """
        dotnetstore-security <command> [options]

        Commands:
          secret [--bytes 64]        Random base64 secret (HS256 signing key, signed-data key)
          encryption-key             256-bit AES key for EncryptionOptions.Keys
          pepper                     Pepper for Argon2Options.Peppers
          rsa [--bits 3072]          RSA key pair (PEM) for RS256
          ec                         P-256 key pair (PEM) for ES256
          calibrate [--target-ms 250] [--memory-kib 65536] [--parallelism 4]
                                     Find Argon2id iterations that take about the target time on this machine
          help                       Show this message

        Store generated secrets in a secret store. Never commit them to source control.
        """;

    /// <summary>Runs a command.</summary>
    /// <param name="args">The command-line arguments.</param>
    /// <param name="output">Where results are written.</param>
    /// <param name="error">Where errors and usage for invalid input are written.</param>
    /// <returns>The process exit code: 0 on success, 1 for an unknown command, 2 for invalid options.</returns>
    internal static int Run(string[] args, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            output.WriteLine(Usage);
            return 0;
        }

        try
        {
            var options = ParseOptions(args.AsSpan(1));

            switch (args[0])
            {
                case "secret":
                    output.WriteLine(KeyGenerator.CreateSecret(GetInt(options, "bytes", 64)));
                    return 0;

                case "encryption-key":
                    output.WriteLine(KeyGenerator.CreateEncryptionKey());
                    return 0;

                case "pepper":
                    output.WriteLine(KeyGenerator.CreatePepper());
                    return 0;

                case "rsa":
                    WriteKeyPair(output, KeyGenerator.CreateRsaKeyPair(GetInt(options, "bits", 3072)));
                    return 0;

                case "ec":
                    WriteKeyPair(output, KeyGenerator.CreateEcKeyPair());
                    return 0;

                case "calibrate":
                    Calibrate(options, output);
                    return 0;

                default:
                    error.WriteLine($"Unknown command '{args[0]}'.");
                    error.WriteLine(Usage);
                    return 1;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
        {
            error.WriteLine(ex.Message);
            return 2;
        }
    }

    private static void Calibrate(Dictionary<string, string> options, TextWriter output)
    {
        var targetMs = GetInt(options, "target-ms", 250);
        var memory = GetInt(options, "memory-kib", 65_536);
        var parallelism = GetInt(options, "parallelism", 4);

        output.WriteLine($"Calibrating Argon2id for about {targetMs} ms at {memory} KiB, {parallelism} lanes...");
        var (result, elapsed) = Argon2Calibrator.Calibrate(TimeSpan.FromMilliseconds(targetMs), memory, parallelism);

        output.WriteLine($"MemorySizeKiB: {result.MemorySizeKiB}");
        output.WriteLine($"Iterations: {result.Iterations}");
        output.WriteLine($"DegreeOfParallelism: {result.DegreeOfParallelism}");
        output.WriteLine($"One hash took {elapsed.TotalMilliseconds:F0} ms on this machine.");
    }

    private static void WriteKeyPair(TextWriter output, (string PrivateKeyPem, string PublicKeyPem) pair)
    {
        output.WriteLine("Private key (issuer only):");
        output.WriteLine(pair.PrivateKeyPem.TrimEnd());
        output.WriteLine();
        output.WriteLine("Public key (services that only validate):");
        output.WriteLine(pair.PublicKeyPem.TrimEnd());
    }

    private static Dictionary<string, string> ParseOptions(ReadOnlySpan<string> args)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);

        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
            {
                throw new ArgumentException($"Unexpected argument '{args[i]}'. Options look like '--name value'.");
            }

            options[args[i][2..]] = args[++i];
        }

        return options;
    }

    private static int GetInt(Dictionary<string, string> options, string name, int defaultValue) =>
        options.TryGetValue(name, out var text)
            ? int.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture)
            : defaultValue;
}
