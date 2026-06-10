using System.Diagnostics;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// veraPDF interop tests: validates that documents incrementally signed by SimpleSign
/// preserve PDF/A conformance as verified by the veraPDF validator (Docker).
///
/// Uses known-good PDF/A-2b and PDF/A-3b corpus files from the veraPDF test suite
/// as source documents, signs them via <see cref="SimpleSigner"/> (once, twice, thrice),
/// and asserts that every intermediate output passes veraPDF validation.
/// </summary>
[Trait("Category", "Interop")]
[Trait("Category", "VeraPdf")]
public sealed class VeraPdfInteropTests(ITestOutputHelper output)
{
    private const string ResourcePrefix = "SimpleSign.Interop.Tests.corpus.verapdf.";
    private const string VeraPdfImage = "verapdf/cli";

    private static byte[] LoadEmbedded(string filename)
    {
        var assembly = typeof(VeraPdfInteropTests).Assembly;
        var stream = assembly.GetManifestResourceStream(ResourcePrefix + filename)
            ?? assembly.GetManifestResourceStream(ResourcePrefix + filename.Replace('-', '_'));
        if (stream is null)
        {
            var available = string.Join(", ", assembly.GetManifestResourceNames()
                .Where(n => n.Contains("verapdf")));
            throw new FileNotFoundException(
                $"Embedded corpus resource '{filename}' not found. Available: {available}");
        }
        using (stream)
        {
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return bytes;
        }
    }

    private static async Task<(string stdout, string stderr, int exitCode)> RunVeraPdf(
        byte[] pdf, string flavour)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"verapdf-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        try
        {
            var inputPath = Path.Combine(tmpDir, "input.pdf");
            await File.WriteAllBytesAsync(inputPath, pdf);

            var psi = new ProcessStartInfo("docker",
                $"run --rm -v {tmpDir}:/data {VeraPdfImage} verapdf --format text --flavour {flavour} -- /data/input.pdf")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var proc = Process.Start(psi)!;
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (stdout, stderr, proc.ExitCode);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static void SkipIfVeraPdfUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists(VeraPdfImage),
            $"veraPDF CLI image not pulled. Run: docker pull {VeraPdfImage}");
    }

    // ──────────────────────────────────────────────────────────────────────
    // PDF/A-3b tests
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "PDF/A-3b: single signature preserves conformance (veraPDF)")]
    public async Task SingleSignature_Preserves_PdfA3b()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-3b-6-8-t02-pass-a.pdf");
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 3b Single");

        byte[] signed = await SimpleSigner
            .Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        var (stdout, stderr, exitCode) = await RunVeraPdf(signed, "3b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("PASS /data/input.pdf 3b");
    }

    [SkippableFact(DisplayName = "PDF/A-3b: double signature preserves conformance (veraPDF)")]
    public async Task DoubleSignature_Preserves_PdfA3b()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-3b-6-8-t02-pass-a.pdf");
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 3b First");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 3b Second");

        byte[] afterFirst = await SimpleSigner
            .Document(pdf)
            .WithCertificate(cert1)
            .WithPdfAPreservation()
            .SignAsync();

        byte[] afterSecond = await SimpleSigner
            .Document(afterFirst)
            .WithCertificate(cert2)
            .WithPdfAPreservation()
            .SignAsync();

        var (stdout, stderr, exitCode) = await RunVeraPdf(afterSecond, "3b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("PASS /data/input.pdf 3b");
    }

    [SkippableFact(DisplayName = "PDF/A-3b: triple signature preserves conformance (veraPDF)")]
    public async Task TripleSignature_Preserves_PdfA3b()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-3b-6-8-t02-pass-a.pdf");
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 3b S1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 3b S2");
        using var cert3 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 3b S3");

        byte[] result = pdf;
        foreach (var cert in new[] { cert1, cert2, cert3 })
        {
            result = await SimpleSigner
                .Document(result)
                .WithCertificate(cert)
                .WithPdfAPreservation()
                .SignAsync();
        }

        var (stdout, stderr, exitCode) = await RunVeraPdf(result, "3b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("PASS /data/input.pdf 3b");
    }

    // ──────────────────────────────────────────────────────────────────────
    // PDF/A-2b tests
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "PDF/A-2b: single signature preserves conformance (veraPDF)")]
    public async Task SingleSignature_Preserves_PdfA2b()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-2b-6-1-2-t02-pass-a.pdf");
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 2b Single");

        byte[] signed = await SimpleSigner
            .Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        var (stdout, stderr, exitCode) = await RunVeraPdf(signed, "2b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("PASS /data/input.pdf 2b");
    }

    [SkippableFact(DisplayName = "PDF/A-2b: double signature preserves conformance (veraPDF)")]
    public async Task DoubleSignature_Preserves_PdfA2b()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-2b-6-1-2-t02-pass-a.pdf");
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 2b First");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF 2b Second");

        byte[] afterFirst = await SimpleSigner
            .Document(pdf)
            .WithCertificate(cert1)
            .WithPdfAPreservation()
            .SignAsync();

        byte[] afterSecond = await SimpleSigner
            .Document(afterFirst)
            .WithCertificate(cert2)
            .WithPdfAPreservation()
            .SignAsync();

        var (stdout, stderr, exitCode) = await RunVeraPdf(afterSecond, "2b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("PASS /data/input.pdf 2b");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Sanity check: tampered document must be rejected
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "PDF/A-3b: tampered signature is rejected by veraPDF")]
    public async Task TamperedSignature_RejectedByVeraPdf()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-3b-6-8-t02-pass-a.pdf");
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Tamper");

        byte[] signed = await SimpleSigner
            .Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        // Corrupt a byte in the original PDF content (before the incremental signature update)
        // to simulate document tampering.
        byte[] original = LoadEmbedded("PDF_A-3b-6-8-t02-pass-a.pdf");
        signed.AsSpan(0, original.Length)[original.Length / 2] ^= 0xFF;

        var (stdout, stderr, exitCode) = await RunVeraPdf(signed, "3b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("FAIL /data/input.pdf 3b");
    }
}
