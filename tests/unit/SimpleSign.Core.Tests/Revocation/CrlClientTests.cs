using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

public sealed class CrlClientTests
{
    // ── CRL builder helpers ──────────────────────────────────────────────────

    private static byte[] BuildCrl(
        byte[] issuerNameRawData,
        byte[]? revokedSerial = null,
        DateTimeOffset? nextUpdate = null,
        bool v2 = false)
    {
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence()) // TBSCertList
        {
            // version INTEGER (bare, no context tag) — only present in v2 CRLs
            if (v2)
                tbsWriter.WriteInteger(1);

            // signature AlgorithmIdentifier (sha256WithRSAEncryption)
            using (tbsWriter.PushSequence())
            {
                tbsWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                tbsWriter.WriteNull();
            }

            // issuer Name
            tbsWriter.WriteEncodedValue(issuerNameRawData);

            // thisUpdate UTCTime
            tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));

            // nextUpdate UTCTime (optional)
            if (nextUpdate.HasValue)
                tbsWriter.WriteUtcTime(nextUpdate.Value);

            // revokedCertificates (optional)
            if (revokedSerial is not null)
            {
                using (tbsWriter.PushSequence()) // SEQUENCE OF
                {
                    using (tbsWriter.PushSequence()) // single entry
                    {
                        tbsWriter.WriteInteger(revokedSerial);
                        tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
                    }
                }
            }
        }

        byte[] tbsBytes = tbsWriter.Encode();

        var crlWriter = new AsnWriter(AsnEncodingRules.DER);
        using (crlWriter.PushSequence()) // CertificateList
        {
            crlWriter.WriteEncodedValue(tbsBytes);

            // signatureAlgorithm
            using (crlWriter.PushSequence())
            {
                crlWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                crlWriter.WriteNull();
            }

            // signatureValue BIT STRING (dummy)
            crlWriter.WriteBitString(new byte[256]);
        }

        return crlWriter.Encode();
    }

    private static byte[] BuildSignedCrl(X509Certificate2 caCertWithKey, byte[]? revokedSerial = null)
    {
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence())
        {
            using (tbsWriter.PushSequence())
            {
                tbsWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                tbsWriter.WriteNull();
            }

            tbsWriter.WriteEncodedValue(caCertWithKey.SubjectName.RawData);
            tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
            tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddYears(1));

            if (revokedSerial is not null)
            {
                using (tbsWriter.PushSequence())
                {
                    using (tbsWriter.PushSequence())
                    {
                        tbsWriter.WriteInteger(revokedSerial);
                        tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
                    }
                }
            }
        }

        byte[] tbsBytes = tbsWriter.Encode();

        using var rsa = caCertWithKey.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(tbsBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var crlWriter = new AsnWriter(AsnEncodingRules.DER);
        using (crlWriter.PushSequence())
        {
            crlWriter.WriteEncodedValue(tbsBytes);

            using (crlWriter.PushSequence())
            {
                crlWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                crlWriter.WriteNull();
            }

            crlWriter.WriteBitString(signature);
        }

        return crlWriter.Encode();
    }

    // ── Static method tests ──────────────────────────────────────────────────

    [Fact(DisplayName = "Certificate without CDP returns null CRL URL")]
    public void GetCrlUrl_CertWithoutCdp_ReturnsNull()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        CrlClient.GetCrlUrl(cert).ShouldBeNull();
    }

    [Fact(DisplayName = "Empty CRL returns false for non-revoked serial")]
    public void IsSerialInCrl_EmptyCrl_ReturnsFalse()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        CrlClient.IsSerialInCrl(leaf, crl)!.Value.ShouldBeFalse();
    }

    [Fact(DisplayName = "Serial present in CRL returns true")]
    public void IsSerialInCrl_CertInCrl_ReturnsTrue()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        byte[] serial = [0x01, 0x02, 0x03];
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer, serialNumber: serial);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, revokedSerial: serial,
            nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        CrlClient.IsSerialInCrl(leaf, crl)!.Value.ShouldBeTrue();
    }

    [Fact(DisplayName = "CRL issuer mismatch returns null")]
    public void IsSerialInCrl_CrlIssuerMismatch_ReturnsNull()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        using var otherIssuer = TestCertificateFactory.CreateCaCert("CN=Other CA, O=Other");
        byte[] crl = BuildCrl(otherIssuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        CrlClient.IsSerialInCrl(leaf, crl).ShouldBeNull();
    }

    [Fact(DisplayName = "Expired CRL returns null")]
    public void IsSerialInCrl_ExpiredCrl_ReturnsNull()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        CrlClient.IsSerialInCrl(leaf, crl).ShouldBeNull();
    }

    [Fact(DisplayName = "Valid CRL signature returns true")]
    public void VerifyCrlSignature_ValidSignature_ReturnsTrue()
    {
        using var ca = TestCertificateFactory.CreateCaCert();
        byte[] crl = BuildSignedCrl(ca);

        // Extract tbsCertList, signature from the CRL
        var reader = new AsnReader(crl, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        byte[] tbsData = seq.PeekEncodedValue().ToArray();
        seq.ReadSequence(); // skip tbs
        var sigAlgSeq = seq.ReadSequence();
        string sigAlgOid = sigAlgSeq.ReadObjectIdentifier();
        byte[] signature = seq.ReadBitString(out _);

        CrlClient.VerifyCrlSignature(ca, tbsData, signature, sigAlgOid).ShouldBeTrue();
    }

    [Fact(DisplayName = "Invalid CRL signature returns false")]
    public void VerifyCrlSignature_InvalidSignature_ReturnsFalse()
    {
        using var ca = TestCertificateFactory.CreateCaCert();

        byte[] tbsData = [0x30, 0x03, 0x01, 0x01, 0xFF];
        byte[] badSignature = new byte[256];

        CrlClient.VerifyCrlSignature(ca, tbsData, badSignature, "1.2.840.113549.1.1.11")
            .ShouldBeFalse();
    }

    [Fact(DisplayName = "CRL issuer encoded as UTF8String matches cert issuer encoded as PrintableString")]
    public void IsSerialInCrl_IssuerEncodingMismatch_NormalizedComparisonSucceeds()
    {
        // Simulate a real-world scenario (e.g., Brazilian ICP-Brasil / Gov.br CAs) where the CRL
        // encodes its issuer DN using UTF8String but the certificate's IssuerName uses PrintableString
        // for the same string values. The raw bytes differ but the DN values are identical.
        using var issuer = TestCertificateFactory.CreateCaCert("CN=Test CA, O=Org, C=BR");
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        // Re-encode the issuer DN with UTF8String instead of whatever the cert uses
        byte[] utf8IssuerBytes = BuildDnWithUtf8String("Test CA", "Org", "BR");
        byte[] crl = BuildCrl(utf8IssuerBytes, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        // Should NOT return null (should recognize the issuer despite encoding mismatch)
        CrlClient.IsSerialInCrl(leaf, crl).ShouldNotBeNull(
            "CRL with same DN values but different string encoding should be accepted");
        CrlClient.IsSerialInCrl(leaf, crl)!.Value.ShouldBeFalse(
            "non-revoked certificate should not be in CRL");
    }

    /// <summary>Builds a raw X.500 DN with UTF8String-encoded values (mirrors Brazilian CA CRL encoding).</summary>
    private static byte[] BuildDnWithUtf8String(string cn, string o, string c)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // Name SEQUENCE
        {
            // C= (always PrintableString per RFC)
            using (writer.PushSetOf())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("2.5.4.6"); // id-at-countryName
                    writer.WriteCharacterString(UniversalTagNumber.PrintableString, c);
                }
            }

            // O= (UTF8String — this differs from certs that use PrintableString here)
            using (writer.PushSetOf())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("2.5.4.10"); // id-at-organizationName
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, o);
                }
            }

            // CN= (UTF8String)
            using (writer.PushSetOf())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("2.5.4.3"); // id-at-commonName
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, cn);
                }
            }
        }

        return writer.Encode();
    }

    [Fact(DisplayName = "v2 CRL (with bare version INTEGER) is parsed correctly")]
    public void IsSerialInCrl_V2CrlWithVersionField_Parsed()
    {
        // RFC 5280 v2 CRLs prepend a bare INTEGER (value=1) before the AlgorithmIdentifier.
        // This matches the structure of real Brazilian ICP-Brasil / Gov.br CRLs.
        using var issuer = TestCertificateFactory.CreateCaCert();
        byte[] serial = [0x0A, 0x0B, 0x0C];
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer, serialNumber: serial);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, revokedSerial: serial,
            nextUpdate: DateTimeOffset.UtcNow.AddYears(1), v2: true);

        CrlClient.IsSerialInCrl(leaf, crl)!.Value.ShouldBeTrue(
            "v2 CRL with bare version INTEGER should be parsed and revoked cert found");
    }

    // ── Instance method tests (mocked HTTP) ──────────────────────────────────

    [Fact(DisplayName = "CRL check via HTTP with empty CRL returns true")]
    public async Task CheckCrlAsync_EmptyCrl_ReturnsTrue()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));
        using var httpClient = MockHttpHandler.ForGetBytes(crl);

        var client = new CrlClient(httpClient);
        bool result = await client.CheckCrlAsync(leaf, "http://example.com/test.crl", CancellationToken.None);

        result.ShouldBeTrue();
    }

    [Fact(DisplayName = "CRL network failure throws HttpRequestException")]
    public async Task CheckCrlAsync_NetworkFailure_ThrowsHttpRequestException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        using var httpClient = MockHttpHandler.Failing();

        var client = new CrlClient(httpClient);

        var act = async () => await client.CheckCrlAsync(cert, "http://example.com/test.crl", CancellationToken.None);
        await Should.ThrowAsync<HttpRequestException>(act);
    }
}
