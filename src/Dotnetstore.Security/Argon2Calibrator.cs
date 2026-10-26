using System.Diagnostics;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;

namespace Dotnetstore.Security;

/// <summary>
/// Finds Argon2id cost settings that take about a target time on the current machine.
/// Run it on hardware like your production servers, since the result depends on the CPU and memory speed.
/// </summary>
public static class Argon2Calibrator
{
    /// <summary>
    /// Finds the smallest number of iterations at the given memory size whose hashing time reaches
    /// <paramref name="targetTime"/>.
    /// </summary>
    /// <param name="targetTime">The desired time for one hash. Around 250 ms is a common choice for interactive logins.</param>
    /// <param name="memorySizeKiB">The memory cost to calibrate at. Defaults to 65536 (64 MiB).</param>
    /// <param name="degreeOfParallelism">The number of lanes. Defaults to 4.</param>
    /// <returns>
    /// Options with the calibrated iteration count, and the time one hash took with them.
    /// If a single iteration is already slower than the target, one iteration is returned.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="targetTime"/> is not positive.</exception>
    public static (Argon2Options Options, TimeSpan Elapsed) Calibrate(
        TimeSpan targetTime,
        int memorySizeKiB = 65_536,
        int degreeOfParallelism = 4)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(targetTime, TimeSpan.Zero);

        var options = new Argon2Options
        {
            MemorySizeKiB = memorySizeKiB,
            DegreeOfParallelism = degreeOfParallelism,
            Iterations = 1,
        };
        options.Validate();

        // Warm up so JIT and allocation costs do not skew the first measurement.
        _ = Measure(options);

        var elapsed = TimeSpan.Zero;
        for (var iterations = 1; iterations <= Argon2Options.MaxIterations; iterations++)
        {
            options.Iterations = iterations;
            elapsed = Measure(options);

            if (elapsed >= targetTime)
            {
                break;
            }
        }

        return (options, elapsed);
    }

    private static TimeSpan Measure(Argon2Options options)
    {
        var handler = new HashHandler(options);
        var stopwatch = Stopwatch.StartNew();
        _ = handler.Hash("calibration");
        return stopwatch.Elapsed;
    }
}
