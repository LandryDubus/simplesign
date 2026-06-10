using System.Diagnostics;

namespace SimpleSign.Interop.Tests;

internal static class DockerProbe
{
    /// <summary>Returns true if <c>docker info</c> succeeds within 5 seconds.</summary>
    public static bool IsDockerAvailable() => RunProbe("docker", "info");

    /// <summary>Returns true if the named Docker image is locally available.</summary>
    public static bool ImageExists(string image) => RunProbe("docker", $"image inspect {image}");

    private static bool RunProbe(string command, string args, int timeoutMs = 10_000)
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
            Task.WaitAll(stdoutTask, stderrTask);

            return exited && p.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
