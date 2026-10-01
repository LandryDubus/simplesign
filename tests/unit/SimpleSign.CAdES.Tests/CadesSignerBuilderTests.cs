using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Shouldly;
using Xunit;

namespace SimpleSign.CAdES.Tests;

public sealed class CadesSignerBuilderTests : IDisposable
{
    private readonly X509Certificate2 _cert;
    private readonly byte[] _data;
    private readonly SyntheticPki _pki;

    public CadesSignerBuilderTests()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert();
        _data = "test data for signing"u8.ToArray();
        _pki = new SyntheticPki("http://mock-tsa.example.com/crl");
    }

    public void Dispose()
    {
        _cert.Dispose();
        _pki.Dispose();
    }

    [Fact]
    public async Task SignAsync_WithCertificate_ReturnsValidSignature()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        cms.ShouldNotBeNull();
        cms.Length.ShouldBeGreaterThan(0);

        var parsed = CmsParser.Parse(cms);
        parsed.SignerCertificate.ShouldNotBeNull();
        parsed.MessageDigest.ShouldNotBeNull();
        parsed.Signature.ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_WithLevelBasic_ReturnsValidDetachedSignature()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithLevel(AdesBaselineProfile.Basic())
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureTimestampToken.ShouldBeNull();
        parsed.UnsignedAttributes.ShouldBeNull();
        parsed.SignerCertificate.ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_WithLevelTimestamped_CreatesTimestampedCms()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient))))
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureTimestampToken.ShouldNotBeNull();
        parsed.UnsignedAttributes.ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_WithLevelLongTerm_EmbedsLtvData()
    {
        var mockTsa = BuildValidLtvHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_pki.Leaf, [_pki.IntermediateCa, _pki.RootCa])
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureTimestampToken.ShouldNotBeNull();
        parsed.UnsignedAttributes.ShouldNotBeNull();
        parsed.UnsignedAttributes!.ContainsKey(Oids.CertValues).ShouldBeFalse();
        parsed.UnsignedAttributes.ContainsKey(Oids.RevocationValues).ShouldBeFalse();
        parsed.Certificates.Count.ShouldBeGreaterThan(1);
    }

    [Fact]
    public async Task SignAsync_WithLevelArchive_AppliesArchiveTimestamp()
    {
        var mockTsa = BuildValidLtvHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_pki.Leaf, [_pki.IntermediateCa, _pki.RootCa])
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureTimestampToken.ShouldNotBeNull();
        parsed.ArchiveTimestampToken.ShouldNotBeNull();
        parsed.UnsignedAttributes.ShouldNotBeNull();
        Oids.ArchiveTimeStamp.ShouldBe("0.4.0.1733.2.4");
        CmsParser.Parse(parsed.ArchiveTimestampToken!).UnsignedAttributes!
            .ContainsKey(Oids.AtsHashIndexV3).ShouldBeTrue();
        parsed.UnsignedAttributes!.ContainsKey(Oids.ArchiveTimeStamp).ShouldBeTrue();
    }

    [Fact]
    public async Task SignWithDetailsAsync_Basic_ReturnsWarnings()
    {
        var result = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignWithDetailsAsync();

        result.SignedArtifact.ShouldNotBeNull();
        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.HasSignatureTimestamp.ShouldBeFalse();
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.HasArchiveTimestamp.ShouldBeFalse();
        result.Warnings.ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_WithContentTypeEnveloped_ReturnsP7m()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithContentType(CadesContentType.Enveloped)
            .SignAsync();

        cms.ShouldNotBeNull();
        cms.Length.ShouldBeGreaterThan(0);

        var parsed = CmsParser.Parse(cms);
        parsed.SignerCertificate.ShouldNotBeNull();
        parsed.MessageDigest.ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_WithCommitmentType_IncludesAttribute()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithCommitmentType(CommitmentType.ProofOfOrigin)
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.CommitmentTypeOid.ShouldBe(Oids.ProofOfOrigin);
    }

    [Fact]
    public async Task SignAsync_WithSignaturePolicy_IncludesOid()
    {
        var policyOid = "2.16.76.1.7.1.1.1.1";

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignaturePolicy(policyOid, "https://example.com/policy")
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.SignaturePolicyOid.ShouldBe(policyOid);
    }

    [Fact]
    public async Task SignAsync_WithHashAlgorithm_UsesSpecifiedAlgorithm()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.DigestAlgorithmOid.ShouldBe(Oids.Sha512);
    }

    [Fact]
    public async Task SignAsync_NoCertificate_ThrowsSigningException()
    {
        await Should.ThrowAsync<SigningException>(async () =>
        {
            await CadesSigner.Document(_data).SignAsync();
        });
    }

    [Fact]
    public async Task SignAsync_WithExternalSigner_ReturnsValidSignature()
    {
        var cms = await CadesSigner.Document(_data)
            .WithExternalSigner(_cert, new FuncExternalSigner(async signedAttrs =>
            {
                using var key = _cert.GetRSAPrivateKey()!;
                return await Task.FromResult(
                    key.SignData(signedAttrs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm(Oids.RsaSha256)
            .SignAsync();

        cms.ShouldNotBeNull();
        cms.Length.ShouldBeGreaterThan(0);

        var parsed = CmsParser.Parse(cms);
        parsed.SignerCertificate.ShouldNotBeNull();
        parsed.Signature.ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_ExternalSignerWithDetails_ReturnsCorrectMetadata()
    {
        var result = await CadesSigner.Document(_data)
            .WithExternalSigner(_cert, new FuncExternalSigner(async signedAttrs =>
            {
                using var key = _cert.GetRSAPrivateKey()!;
                return await Task.FromResult(
                    key.SignData(signedAttrs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm(Oids.RsaSha256)
            .SignWithDetailsAsync();

        result.SignedArtifact.ShouldNotBeNull();
        result.HasSignatureTimestamp.ShouldBeFalse();
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.HasArchiveTimestamp.ShouldBeFalse();
    }

    [Fact]
    public async Task SignAsync_ExternalSignerAutoDetectOid_ReturnsValidSignature()
    {
        var cms = await CadesSigner.Document(_data)
            .WithExternalSigner(_cert, new FuncExternalSigner(async signedAttrs =>
            {
                using var key = _cert.GetRSAPrivateKey()!;
                return await Task.FromResult(
                    key.SignData(signedAttrs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .SignAsync();

        cms.ShouldNotBeNull();
        cms.Length.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task SignAsync_WithExtraCertificates_IncludesChain()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.Certificates.ShouldContain(c => c.Subject == _pki.IntermediateCa.Subject);
    }

    [Fact]
    public async Task SignAsync_WithOperationId_SetsId()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithOperationId("op-12345")
            .SignAsync();

        cms.ShouldNotBeNull();
        cms.Length.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task SignAsync_WithSigningTime_SetsTime()
    {
        var signingTime = DateTimeOffset.UtcNow.AddDays(-1);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSigningTime(signingTime)
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.SigningTime.ShouldNotBeNull();
        parsed.SigningTime.Value.UtcDateTime.ShouldBe(
            new DateTimeOffset(signingTime.UtcDateTime, TimeSpan.Zero).UtcDateTime,
            tolerance: TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task SignAsync_WithExtraCertificatesAndLevelLongTerm_IncludesChainInCms()
    {
        var mockTsa = BuildValidLtvHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_pki.Leaf, [_pki.IntermediateCa, _pki.RootCa])
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        parsed.Certificates.ShouldContain(c => c.Subject == _pki.IntermediateCa.Subject);
    }

    [Fact]
    public async Task SignWithDetailsAsync_TimestampedProfile_ReportsTimestampedLevels()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var result = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient))))
            .SignWithDetailsAsync();

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();

        var parsed = CmsParser.Parse(result.SignedArtifact);
        parsed.SignatureTimestampToken.ShouldNotBeNull();
    }

    private static HttpMessageHandler BuildMockTsaHandler() => MockTimestampAuthority.CreateHandler();

    private HttpMessageHandler BuildValidLtvHandler() => MockTimestampAuthority.CreateLtvHandler(_pki);
}
