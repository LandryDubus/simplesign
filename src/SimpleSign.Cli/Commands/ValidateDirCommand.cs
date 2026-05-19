using System.ComponentModel;
using SimpleSign.Brasil;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Validate all PDF signatures in a directory")]
internal sealed class ValidateDirCommand : AsyncCommand<ValidateDirCommand.Settings>
{
    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<directory>")]
        [Description("Directory containing PDF files to validate")]
        public string DirectoryPath { get; init; } = null!;

        [CommandOption("--no-revocation")]
        [Description("Skip CRL/OCSP revocation checks")]
        public bool NoRevocation { get; init; }

        [CommandOption("--concurrency")]
        [Description("Maximum concurrent validations (default: 4)")]
        public int Concurrency { get; init; } = 4;

        [CommandOption("--pattern")]
        [Description("File search pattern (default: *.pdf)")]
        public string Pattern { get; init; } = "*.pdf";

        [CommandOption("--recurse|-r")]
        [Description("Search subdirectories recursively")]
        public bool Recurse { get; init; }

        public override ValidationResult Validate()
        {
            if (!Directory.Exists(DirectoryPath))
            {
                return ValidationResult.Error($"Directory not found: {DirectoryPath}");
            }

            if (Concurrency < 1)
            {
                return ValidationResult.Error("Concurrency must be at least 1.");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var searchOption = settings.Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var files = Directory.GetFiles(settings.DirectoryPath, settings.Pattern, searchOption);

        if (files.Length == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No files matching '{settings.Pattern}' found in {settings.DirectoryPath.EscapeMarkup()}[/]");
            return 0;
        }

        using var loggerFactory = settings.CreateLoggerFactory();
        var options = new ValidationOptions { CheckRevocation = !settings.NoRevocation };
        var brasil = new BrasilExtension();
        var validator = new PdfSignatureValidator(options, httpClient: null,
            logger: settings.CreateLogger<PdfSignatureValidator>(),
            trustAnchorProviders: brasil.TrustAnchorProviders);
        var bulk = new BulkValidator(validator, maxConcurrency: settings.Concurrency,
            logger: loggerFactory?.CreateLogger("SimpleSign.BulkValidation"));

        AnsiConsole.MarkupLine($"[bold]Validating {files.Length} file(s)[/] in [dim]{settings.DirectoryPath.EscapeMarkup()}[/]");
        AnsiConsole.WriteLine();

        int invalidFiles = 0;
        int totalSigs = 0;
        int validSigs = 0;
        int erroredFiles = 0;

        await foreach (var bulkResult in bulk.ValidateFilesAsync(files, cancellationToken).ConfigureAwait(false))
        {
            if (!bulkResult.IsProcessed)
            {
                AnsiConsole.MarkupLine($"[red]✗[/] [bold]{bulkResult.Id.EscapeMarkup()}[/]  [red]ERROR: {bulkResult.Error!.Message.EscapeMarkup()}[/]");
                erroredFiles++;
                continue;
            }

            // Build conformance level map from inspection for the full file path
            var filePath = files.First(f => Path.GetFileName(f) == bulkResult.Id);
            Dictionary<string, PAdESConformanceLevel> conformanceLevels;
            try
            {
                await using var inspectStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
                var inspection = await PdfSignatureInspector.InspectAsync(inspectStream, cancellationToken).ConfigureAwait(false);
                conformanceLevels = ConformanceDetector.DetectAll(inspection)
                    .GroupBy(x => x.Signature.FieldName)
                    .ToDictionary(g => g.Key, g => g.First().Level);
            }
            catch
            {
                conformanceLevels = [];
            }

            ValidateCommand.OutputSimple(filePath, bulkResult.Results!, conformanceLevels);

            var userSigs = bulkResult.Results!.Where(r => !r.IsDocumentTimestamp).ToList();
            totalSigs += userSigs.Count;
            validSigs += userSigs.Count(r => r.IsValid);
            if (userSigs.Any(r => !r.IsValid))
            {
                invalidFiles++;
            }
        }

        // Summary footer
        AnsiConsole.WriteLine();
        var rule = new Rule("[bold]Summary[/]") { Justification = Justify.Left };
        AnsiConsole.Write(rule);

        var totalFiles = files.Length;
        var okFiles = totalFiles - invalidFiles - erroredFiles;
        AnsiConsole.MarkupLine($"Files:      [bold]{totalFiles}[/]  ([green]{okFiles} ok[/] · [red]{invalidFiles} invalid[/] · [red]{erroredFiles} error[/])");
        AnsiConsole.MarkupLine($"Signatures: [bold]{totalSigs}[/]  ([green]{validSigs} valid[/] · [red]{totalSigs - validSigs} invalid[/])");
        AnsiConsole.MarkupLine($"Avg time:   {bulk.AverageElapsedMs:N0} ms/file");
        AnsiConsole.WriteLine();

        return (invalidFiles > 0 || erroredFiles > 0) ? 1 : 0;
    }
}
