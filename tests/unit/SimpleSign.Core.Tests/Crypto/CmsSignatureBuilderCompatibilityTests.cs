using System.Formats.Asn1;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>
/// Tests for <see cref="CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility"/>
/// and the new <c>signatureAlgorithmOid</c> parameter on <see cref="CmsSignatureBuilder.Build"/>.
/// </summary>
public sealed class CmsSignatureBuilderCompatibilityTests
{
    [Theory(DisplayName = "ValidateSignatureAlgorithmCompatibility: compatible pairs do not throw")]
    [InlineData(nameof(Oids.RsaSha256))]
    [InlineData(nameof(Oids.RsaSha384))]
    [InlineData(nameof(Oids.RsaSha512))]
    [InlineData(nameof(Oids.RsaPss))]
    public void ValidateCompatibility_RsaCert_CompatibleOids_DoesNotThrow(string oidFieldName)
    {
        string oid = GetOidValue(oidFieldName);
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        // Should not throw
        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(cert, oid);
    }

    [Theory(DisplayName = "ValidateSignatureAlgorithmCompatibility: incompatible pairs throw ArgumentException")]
    [InlineData(nameof(Oids.EcdsaSha256))]
    [InlineData(nameof(Oids.EcdsaSha384))]
    [InlineData(nameof(Oids.Ed25519))]
    public void ValidateCompatibility_RsaCert_IncompatibleOids_Throws(string oidFieldName)
    {
        string oid = GetOidValue(oidFieldName);
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var ex = Should.Throw<ArgumentException>(
            () => CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(cert, oid));
        ex.Message.ShouldContain("not compatible");
    }

    [Theory(DisplayName = "ValidateSignatureAlgorithmCompatibility: ECDSA cert compatible pairs")]
    [InlineData(nameof(Oids.EcdsaSha256))]
    [InlineData(nameof(Oids.EcdsaSha384))]
    [InlineData(nameof(Oids.EcdsaSha512))]
    public void ValidateCompatibility_EcdsaCert_CompatibleOids_DoesNotThrow(string oidFieldName)
    {
        string oid = GetOidValue(oidFieldName);
        using var cert = TestCertificateFactory.CreateEcdsaCert();
        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(cert, oid);
    }

    [Fact(DisplayName = "Build with signatureAlgorithmOid=RsaPss on RSA cert uses PSS padding")]
    public void Build_WithPssOid_OnRsaCert_UsesPssPadding()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] data = "hello"u8.ToArray();

        byte[] cms = CmsSignatureBuilder.Build(
            data, cert, HashAlgorithmName.SHA256,
            signatureAlgorithmOid: Oids.RsaPss);

        string sigAlgOid = ParseSignerInfoSignatureAlgorithmOid(cms);
        sigAlgOid.ShouldBe(Oids.RsaPss);
    }

    [Fact(DisplayName = "Build with incompatible signatureAlgorithmOid throws ArgumentException")]
    public void Build_WithIncompatibleOid_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(); // RSA
        byte[] data = "hello"u8.ToArray();

        Should.Throw<ArgumentException>(() =>
            CmsSignatureBuilder.Build(
                data, cert, HashAlgorithmName.SHA256,
                signatureAlgorithmOid: Oids.EcdsaSha256));
    }

    // ── EdDSA compatibility tests ─────────────────────────────────────────────

    [Fact(DisplayName = "ValidateSignatureAlgorithmCompatibility: Ed25519 cert with Ed25519 OID passes")]
    public void ValidateCompatibility_Ed25519Cert_CompatibleOids_DoesNotThrow()
    {
        using var cert = TestCertificateFactory.TryCreateEdDsaCert();
        if (cert is null)
        {
            return; // EdDSA not supported on this platform
        }

        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(cert, Oids.Ed25519);
    }

    [Fact(DisplayName = "ValidateSignatureAlgorithmCompatibility: Ed25519 cert with RSA OID throws")]
    public void ValidateCompatibility_Ed25519Cert_IncompatibleRsaOid_Throws()
    {
        using var cert = TestCertificateFactory.TryCreateEdDsaCert();
        if (cert is null)
        {
            return; // EdDSA not supported on this platform
        }

        Should.Throw<ArgumentException>(() =>
            CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(cert, Oids.RsaSha256))
            .Message.ShouldContain("not compatible");
    }

    // ── CMS parsing helper ────────────────────────────────────────────────────

    private static string ParseSignerInfoSignatureAlgorithmOid(byte[] cms)
    {
        var reader = new AsnReader(cms, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();
        contentInfo.ReadObjectIdentifier();
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedDataSeq = signedData.ReadSequence();
        signedDataSeq.ReadInteger();
        var digestAlgs = signedDataSeq.ReadSetOf();
        while (digestAlgs.HasData)
        {
            digestAlgs.ReadSequence();
        }
        signedDataSeq.ReadSequence();
        if (signedDataSeq.HasData &&
            signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            signedDataSeq.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }
        var signerInfos = signedDataSeq.ReadSetOf();
        var signerInfo = signerInfos.ReadSequence();
        signerInfo.ReadInteger();
        signerInfo.ReadSequence();
        signerInfo.ReadSequence();
        signerInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var sigAlg = signerInfo.ReadSequence();
        return sigAlg.ReadObjectIdentifier();
    }

    private static string GetOidValue(string fieldName)
    {
        var field = typeof(Oids).GetField(fieldName,
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        return (string)field!.GetValue(null)!;
    }
}
