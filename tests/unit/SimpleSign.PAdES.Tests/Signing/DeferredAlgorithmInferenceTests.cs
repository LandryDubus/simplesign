using System.Formats.Asn1;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the algorithm-inference fix in <see cref="DeferredSigner.PrepareAsync"/>:
///   - Gap 1: PSS cert's RSASSA-PSS-params are honoured.
///   - Gap 3: RSA PKCS#1 keys ≥ 3072 bits get SHA-384; smaller keys get SHA-256.
///   - <see cref="DeferredSigningOptions.HashAlgorithmExplicitlySet"/> overrides inference.
///   - Explicit <see cref="DeferredSigningOptions.SignatureAlgorithmOid"/> is validated
///     against the cert's public key type.
/// </summary>
public sealed class DeferredAlgorithmInferenceTests
{
    private static byte[] BuildMinimalPdf() => "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();

    [Fact(DisplayName = "PSS cert SHA-512 in PrepareAsync → DigestAlgorithm = SHA512")]
    public async Task PrepareAsync_PssCertSha512_ResolvesSha512()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        result.DigestAlgorithm.ShouldBe("SHA512");
    }

    [Fact(DisplayName = "RSA 4096-bit cert in PrepareAsync → DigestAlgorithm = SHA384")]
    public async Task PrepareAsync_Rsa4096Bit_ResolvesSha384()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        result.DigestAlgorithm.ShouldBe("SHA384");
    }

    [Fact(DisplayName = "HashAlgorithmExplicitlySet=true with SHA-256 on a 4096-bit cert → SHA-256")]
    public async Task PrepareAsync_Rsa4096Bit_ExplicitSetSha256_StaysSha256()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet = true
        };
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "PSS cert SHA-512 with explicit SHA-256 override → SHA-256")]
    public async Task PrepareAsync_PssCertSha512_ExplicitSetSha256_StaysSha256()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet = true
        };
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "Incompatible SignatureAlgorithmOid in PrepareAsync → ArgumentException")]
    public async Task PrepareAsync_IncompatibleOid_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet = true,
            SignatureAlgorithmOid = Oids.EcdsaSha256
        };

        Func<Task> act = () => DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);
        (await Should.ThrowAsync<ArgumentException>(act)).Message
            .ShouldContain("not compatible");
    }

    [Fact(DisplayName = "PSS cert SHA-512 end-to-end: PrepareAsync + CompleteAsync → CMS digest = SHA-512")]
    public async Task CompleteAsync_PssCertSha512_EndToEnd_UsesSha512()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var prepareResult = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        // Sign the signed attributes to produce a raw signature.
        // The test only verifies the CMS digest OID, not signature validation,
        // so any RSA key works here.
        using var signingKey = RSA.Create(2048);
        byte[] rawSignature = signingKey.SignData(
            prepareResult.HashToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        // Complete the signature
        byte[] signedPdf = await DeferredSigner.CompleteAsync(
            prepareResult.SessionData, rawSignature);

        // Extract CMS and verify the digest OID is SHA-512
        string digestOid = ExtractDeferredDigestOid(signedPdf);
        digestOid.ShouldBe(Oids.Sha512);
    }

    private static string ExtractDeferredDigestOid(byte[] signedPdf)
    {
        // Locate /Contents <hex...> in the PDF (the last occurrence is the new signature)
        ReadOnlySpan<byte> data = signedPdf;
        int lastContents = data.LastIndexOf("/Contents"u8);
        if (lastContents < 0)
        {
            throw new InvalidOperationException("/Contents marker not found in signed PDF.");
        }

        int hexStart = lastContents + "/Contents"u8.Length;
        while (hexStart < data.Length && (data[hexStart] == (byte)' ' || data[hexStart] == (byte)'\n' || data[hexStart] == (byte)'\r'))
        {
            hexStart++;
        }

        if (data[hexStart] != (byte)'<')
        {
            throw new InvalidOperationException("/Contents value is not a hex string.");
        }

        int hexBegin = hexStart + 1;
        int hexEnd = data[hexBegin..].IndexOf((byte)'>');
        if (hexEnd < 0)
        {
            throw new InvalidOperationException("Unterminated /Contents hex string.");
        }
        hexEnd += hexBegin;

        ReadOnlySpan<byte> hexSpan = data[hexBegin..hexEnd];
        int cmsEnd = hexSpan.Length;
        while (cmsEnd >= 2 && hexSpan[cmsEnd - 2] == (byte)'0' && hexSpan[cmsEnd - 1] == (byte)'0')
        {
            cmsEnd -= 2;
        }

        byte[] cmsBytes = new byte[cmsEnd / 2];
        for (int i = 0; i < cmsBytes.Length; i++)
        {
            cmsBytes[i] = (byte)((HexDigit(hexSpan[2 * i]) << 4) | HexDigit(hexSpan[2 * i + 1]));
        }

        return ParseSignerInfoDigestOid(cmsBytes);
    }

    private static string ParseSignerInfoDigestOid(byte[] cms)
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
        var digestAlg = signerInfo.ReadSequence();
        return digestAlg.ReadObjectIdentifier();
    }

    private static int HexDigit(byte b) => b switch
    {
        (byte)'0' => 0,
        (byte)'1' => 1,
        (byte)'2' => 2,
        (byte)'3' => 3,
        (byte)'4' => 4,
        (byte)'5' => 5,
        (byte)'6' => 6,
        (byte)'7' => 7,
        (byte)'8' => 8,
        (byte)'9' => 9,
        (byte)'a' or (byte)'A' => 10,
        (byte)'b' or (byte)'B' => 11,
        (byte)'c' or (byte)'C' => 12,
        (byte)'d' or (byte)'D' => 13,
        (byte)'e' or (byte)'E' => 14,
        (byte)'f' or (byte)'F' => 15,
        _ => throw new InvalidOperationException($"Invalid hex digit: 0x{b:X2}")
    };
}
