using System.Collections.Concurrent;
using System.Diagnostics;

namespace SimpleSign.Interop.Tests;

internal static class DockerProbe
{
    private static readonly Lazy<bool> Availability = new(
        () => RunProbe("docker", "info"),
        LazyThreadSafetyMode.ExecutionAndPublication);

    private static readonly ConcurrentDictionary<string, Lazy<bool>> ImageProbes =
        new(StringComparer.Ordinal);

    /// <summary>Returns true if <c>docker info</c> succeeds within 30 seconds.</summary>
    public static bool IsDockerAvailable() => Availability.Value;

    /// <summary>Returns true if the named Docker image is locally available.</summary>
    public static bool ImageExists(string image) => ImageProbes.GetOrAdd(
        image,
        static imageName => new Lazy<bool>(
            () => RunProbe("docker", $"image inspect {imageName}"),
            LazyThreadSafetyMode.ExecutionAndPublication)).Value;

    private static bool RunProbe(string command, string args, int timeoutMs = 30_000)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo(command, args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                },
            };
            p.Start();

            // Drain stdout/stderr in parallel to prevent buffer deadlock
            var stdoutTask = Task.Run(() => p.StandardOutput.ReadToEnd());
            var stderrTask = Task.Run(() => p.StandardError.ReadToEnd());
            bool exited = p.WaitForExit(timeoutMs);
            if (!exited)
            {
                p.Kill(entireProcessTree: true);
                p.WaitForExit();
            }
            Task.WaitAll(stdoutTask, stderrTask);

            return exited && p.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
