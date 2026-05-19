using System.ComponentModel;
using Microsoft.Extensions.Logging;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

internal class CommonSettings : CommandSettings
{
    [CommandOption("--verbose|-v")]
    [Description("Enable detailed logging (writes to stderr)")]
    public bool Verbose { get; init; }

    public ILoggerFactory? CreateLoggerFactory() => Verbose ? new CliConsoleLoggerFactory(LogLevel.Debug) : null;

    public ILogger<T>? CreateLogger<T>() => Verbose ? new CliConsoleLogger<T>(LogLevel.Debug) : null;
}
