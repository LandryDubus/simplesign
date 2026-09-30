using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
public class DeferredBuilderBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;
    private RSA _rsa = null!;

    private byte[] _sessionData = null!;
    private byte[] _signedHash = null!;
    private byte[] _sessionIntegrityKey = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _sessionIntegrityKey = RandomNumberGenerator.GetBytes(32);
        _rsa = RSA.Create(2048);

        var req = new CertificateRequest("CN=Bench DeferredBuilder", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var prepResult = await DeferredSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithSessionIntegrityKey(_sessionIntegrityKey)
            .PrepareAsync();
        _sessionData = prepResult.SessionData;
        _signedHash = _rsa.SignData(prepResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cert.Dispose();
        _rsa.Dispose();
    }

    [Benchmark(Baseline = true, Description = "Deferred builder: PrepareAsync")]
    public async Task<byte[]> Prepare()
    {
        var result = await DeferredSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithSessionIntegrityKey(_sessionIntegrityKey)
            .PrepareAsync();
        return result.HashToSign;
    }

    [Benchmark(Description = "Deferred builder: CompleteAsync")]
    public async Task<byte[]> Complete() =>
        await DeferredSigner.Resume(_sessionData, _sessionIntegrityKey).CompleteAsync(_signedHash);

    [Benchmark(Description = "DeferredSignerBuilder: PrepareAsync")]
    public async Task<byte[]> Builder_Prepare()
    {
        var builder = DeferredSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithSessionIntegrityKey(_sessionIntegrityKey);
        var result = await builder.PrepareAsync();
        return result.HashToSign;
    }

    [Benchmark(Description = "DeferredSignerBuilder: PrepareAsync (full config)")]
    public async Task<byte[]> Builder_PrepareFull()
    {
        var builder = DeferredSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithSessionIntegrityKey(_sessionIntegrityKey)
            .WithFieldOptions(new SignatureFieldOptions
            {
                SignerName = "Bench",
                Reason = "Performance test",
                Location = "Lab"
            });
        var result = await builder.PrepareAsync();
        return result.HashToSign;
    }
}
