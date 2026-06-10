using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
public class DeferredBuilderBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;
    private RSA _rsa = null!;

    private byte[] _sessionData = null!;
    private byte[] _signedHash = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _rsa = RSA.Create(2048);

        var req = new CertificateRequest("CN=Bench DeferredBuilder", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var prepResult = await DeferredSigner.PrepareAsync(_pdfBytes, _cert);
        _sessionData = prepResult.SessionData;
        _signedHash = _rsa.SignData(prepResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cert.Dispose();
        _rsa.Dispose();
    }

    [Benchmark(Baseline = true, Description = "DeferredSigner static: PrepareAsync")]
    public async Task<byte[]> Static_Prepare()
    {
        var result = await DeferredSigner.PrepareAsync(_pdfBytes, _cert);
        return result.HashToSign;
    }

    [Benchmark(Description = "DeferredSigner static: CompleteAsync")]
    public async Task<byte[]> Static_Complete() =>
        await DeferredSigner.CompleteAsync(_sessionData, _signedHash);

    [Benchmark(Description = "DeferredSignerBuilder: PrepareAsync")]
    public async Task<byte[]> Builder_Prepare()
    {
        var builder = new DeferredSignerBuilder(_pdfBytes, _cert);
        var result = await builder.PrepareAsync();
        return result.HashToSign;
    }

    [Benchmark(Description = "DeferredSignerBuilder: PrepareAsync (full config)")]
    public async Task<byte[]> Builder_PrepareFull()
    {
        var builder = new DeferredSignerBuilder(_pdfBytes, _cert)
            .WithSignerName("Bench")
            .WithReason("Performance test")
            .WithLocation("Lab");
        var result = await builder.PrepareAsync();
        return result.HashToSign;
    }
}
