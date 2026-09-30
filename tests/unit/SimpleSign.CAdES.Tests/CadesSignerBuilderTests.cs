using System.Formats.Asn1;
using System.Net;
using System.Net.Http.Headers;
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
    public async Task SignAsync_WithLevelLongTerm_WithoutRevocationData_Throws()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var exception = await Assert.ThrowsAsync<SigningException>(() => CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync());

        exception.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task SignAsync_WithLevelArchive_WithoutCollectibleRevocationData_Throws()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var exception = await Should.ThrowAsync<SigningException>(() => CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync());

        exception.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task ArchiveTimestampV3_HashIndexIsInTimestampTokenAndCoversEtsiPreimage()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        byte[] hashIndex = CadesArchiveTimestampV3.CreateHashIndex(cms, HashAlgorithmName.SHA256);
        byte[] preimage = CadesArchiveTimestampV3.CreateMessageImprintInput(
            cms, _data, HashAlgorithmName.SHA256, hashIndex);
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(preimage, HashAlgorithmName.SHA256);
        byte[] tokenWithHashIndex = CadesArchiveTimestampV3.AddHashIndexToTimestampToken(token, hashIndex);
        byte[] completed = CmsSignatureBuilder.AddUnsignedAttributes(
            cms, [CmsAttribute.Raw(Oids.ArchiveTimeStampV3, tokenWithHashIndex)]);

        var warnings = new List<string>();
        CadesArchiveTimestampV3.Validate(completed, _data, warnings).ShouldBeTrue(string.Join(" ", warnings));

        CmsSignedData document = CmsParser.Parse(completed);
        document.UnsignedAttributes!.ContainsKey(Oids.AtsHashIndexV3).ShouldBeFalse();
        CmsSignedData archiveToken = CmsParser.Parse(tokenWithHashIndex);
        archiveToken.UnsignedAttributes!.ContainsKey(Oids.AtsHashIndexV3).ShouldBeTrue();
    }

    [Fact]
    public async Task HasExpectedLtvEvidence_RequiresEveryCollectedCertificateAndRevocationObject()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        var evidence = new LtvCollectionResult(
            CertificateRawData: [[0x30, 0x01, 0x01], [0x30, 0x01, 0x02]],
            OcspResponses: [[0x30, 0x01, 0x03]],
            Crls: [[0x30, 0x01, 0x04]],
            CertificateEvidence:
            [
                new LtvCertificateEvidence("signer", true) { RevocationEvidenceKind = LtvRevocationEvidenceKind.Ocsp },
                new LtvCertificateEvidence("tsa", true) { RevocationEvidenceKind = LtvRevocationEvidenceKind.Crl },
            ]);
        byte[] withLtv = CmsSignatureBuilder.AddUnsignedAttributes(cms,
        [
            CmsAttribute.CertValues([.. evidence.CertificateRawData]),
            CmsAttribute.RevocationValues([.. evidence.OcspResponses], [.. evidence.Crls]),
        ]);

        CadesSignerBuilder.HasExpectedLtvEvidence(CmsParser.Parse(withLtv), evidence).ShouldBeTrue();

        byte[] incomplete = CmsSignatureBuilder.AddUnsignedAttributes(cms,
        [
            CmsAttribute.CertValues([.. evidence.CertificateRawData]),
            CmsAttribute.RevocationValues([.. evidence.OcspResponses]),
        ]);

        CadesSignerBuilder.HasExpectedLtvEvidence(CmsParser.Parse(incomplete), evidence).ShouldBeFalse();
    }

    [Fact]
    public async Task ArchiveTimestampV3_HashIndexAcceptsAllSignerInfos()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        byte[] multiSignerCms = DuplicateOnlySignerInfo(cms);

        Should.NotThrow(() => CadesArchiveTimestampV3.CreateHashIndex(multiSignerCms, HashAlgorithmName.SHA256));
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
            .WithExternalSigner(_cert, new DelegatingExternalSigner(async signedAttrs =>
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
            .WithExternalSigner(_cert, new DelegatingExternalSigner(async signedAttrs =>
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
            .WithExternalSigner(_cert, new DelegatingExternalSigner(async signedAttrs =>
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
    public async Task SignAsync_WithExtraCertificatesAndTimestampLevel_IncludesChainInCms()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient))))
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

    private static byte[] DuplicateOnlySignerInfo(byte[] cms)
    {
        var reader = new AsnReader(cms, AsnEncodingRules.DER);
        var contentInfo = reader.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        var content = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        var signedData = content.ReadSequence();
        var signedDataPrefix = new List<byte[]>
        {
            signedData.ReadEncodedValue().ToArray(),
            signedData.ReadEncodedValue().ToArray(),
            signedData.ReadEncodedValue().ToArray()
        };

        while (signedData.HasData && signedData.PeekTag().TagClass == TagClass.ContextSpecific)
        {
            signedDataPrefix.Add(signedData.ReadEncodedValue().ToArray());
        }

        var signerInfos = signedData.ReadSetOf();
        byte[] signerInfo = signerInfos.ReadEncodedValue().ToArray();
        signerInfos.HasData.ShouldBeFalse("the source fixture must contain one SignerInfo");

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentType);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            using (writer.PushSequence())
            {
                foreach (byte[] value in signedDataPrefix)
                {
                    writer.WriteEncodedValue(value);
                }

                using (writer.PushSetOf())
                {
                    writer.WriteEncodedValue(signerInfo);
                    writer.WriteEncodedValue(signerInfo);
                }
            }
        }

        return writer.Encode();
    }

    private static MockHttpHandler BuildMockTsaHandler()
    {
        return new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes))
            };
            response.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        });
    }

}
