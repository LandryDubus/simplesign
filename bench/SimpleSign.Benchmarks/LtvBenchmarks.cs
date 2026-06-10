using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
public class LtvBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench LTV");
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Baseline = true, Description = "PAdES-B-B (no timestamp, no LTV)")]
    public async Task<byte[]> Baseline()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .SignAsync();
    }

    [Benchmark(Description = "PAdES-B-T (with timestamp)")]
    public async Task<byte[]> WithTimestamp()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithTimestamp("http://timestamp.digicert.com")
            .SignAsync();
    }

    [Benchmark(Description = "PAdES-B-LT (timestamp + LTV)")]
    public async Task<byte[]> WithLtv()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithTimestamp("http://timestamp.digicert.com")
            .WithLtv()
            .SignAsync();
    }

    [Benchmark(Description = "PAdES-B-LTA (timestamp + LTV + archival)")]
    public async Task<byte[]> WithArchivalTimestamp()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithTimestamp("http://timestamp.digicert.com")
            .WithLtv()
            .WithArchivalTimestamp()
            .SignAsync();
    }
}
