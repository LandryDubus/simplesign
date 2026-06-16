using SimpleSign.Cli.Commands;
using Spectre.Console;
using Spectre.Console.Cli;

var app = new CommandApp();
ConfigureApp(app);
return await app.RunAsync(args);

internal static partial class Program
{
    internal static void ConfigureApp(CommandApp app)
    {
        app.Configure(config =>
        {
            config.SetApplicationName("simplesign");
            config.SetApplicationVersion(
                typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0");

            config.AddCommand<SignCommand>("sign")
                .WithDescription("Sign a PDF document");
            config.AddCommand<ValidateCommand>("validate")
                .WithDescription("Validate PDF signatures");
            config.AddCommand<ValidateDirCommand>("validate-dir")
                .WithDescription("Validate all PDFs in a directory (bulk)");
            config.AddCommand<InspectCommand>("inspect")
                .WithDescription("Inspect signature metadata (no validation)");
            config.AddCommand<ExtractCommand>("extract")
                .WithDescription("Extract CMS signatures from a signed PDF");
            config.AddCommand<ExplainCommand>("explain")
                .WithDescription("Explain PDF signature terms and fields");
            config.AddCommand<HtmlToPdfCommand>("html-to-pdf")
                .WithDescription("Convert an HTML file to PDF");
            config.AddCommand<VersionCommand>("version")
                .WithDescription("Show version information");

            config.AddBranch("cades", cades =>
            {
                cades.AddCommand<CadesSignCommand>("sign")
                    .WithDescription("Sign data with CAdES (CMS/PKCS#7)");
                cades.AddCommand<CadesValidateCommand>("validate")
                    .WithDescription("Validate a CAdES detached signature");
            });

            config.SetExceptionHandler((ex, _) =>
            {
                AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
                return -1;
            });
        });
    }

    internal static async Task<int> RunWithAsync(CommandApp app, string[] args) =>
        await app.RunAsync(args);
}
