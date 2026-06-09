using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the algorithm-inference fix in <see cref="DeferredSignerBuilder"/>:
///   - PSS certs get their RSASSA-PSS-params honoured.
///   - RSA PKCS#1 keys ≥ 3072 bits get SHA-384.
///   - Explicit <c>WithHashAlgorithm(...)</c> on the builder overrides inference
///     (the flag is plumbed through the internal <c>DeferredSigningOptions</c>).
/// </summary>
public sealed class DeferredSignerBuilderAlgorithmInferenceTests
{
    private static byte[] BuildMinimalPdf() => "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();

    [Fact(DisplayName = "PSS cert SHA-512 in DeferredSignerBuilder → DigestAlgorithm = SHA512")]
    public async Task DeferredSignerBuilder_PssCertSha512_ResolvesSha512()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var result = await new DeferredSignerBuilder(BuildMinimalPdf(), cert)
            .PrepareAsync();

        result.DigestAlgorithm.ShouldBe("SHA512");
    }

    [Fact(DisplayName = "RSA 4096-bit cert in DeferredSignerBuilder → DigestAlgorithm = SHA384")]
    public async Task DeferredSignerBuilder_Rsa4096Bit_ResolvesSha384()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var result = await new DeferredSignerBuilder(BuildMinimalPdf(), cert)
            .PrepareAsync();

        result.DigestAlgorithm.ShouldBe("SHA384");
    }

    [Fact(DisplayName = "DeferredSignerBuilder.WithHashAlgorithm(SHA256) on a 4096-bit cert → SHA-256")]
    public async Task DeferredSignerBuilder_Rsa4096Bit_ExplicitHash_StaysSha256()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var result = await new DeferredSignerBuilder(BuildMinimalPdf(), cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .PrepareAsync();

        result.DigestAlgorithm.ShouldBe("SHA256");
    }
}
