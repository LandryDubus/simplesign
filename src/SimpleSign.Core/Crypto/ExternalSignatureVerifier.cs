using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Crypto;

/// <summary>Validates raw external-signature encoding and cryptographic binding before packaging.</summary>
internal static class ExternalSignatureVerifier
{
    internal static void Verify(
        X509Certificate2 certificate,
        ExternalSigningRequest request,
        ReadOnlySpan<byte> signature)
    {
        bool valid;
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            int expectedLength = (rsa.KeySize + 7) / 8;
            valid = signature.Length == expectedLength
                && rsa.VerifyData(
                    request.DataToSign.Span,
                    signature,
                    request.HashAlgorithm,
                    request.SignatureAlgorithmOid == Oids.RsaPss
                        ? RSASignaturePadding.Pss
                        : RSASignaturePadding.Pkcs1);
        }
        else
        {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                ValidateEcdsaDer(signature);
                valid = ecdsa.VerifyData(
                    request.DataToSign.Span,
                    signature,
                    request.HashAlgorithm,
                    DSASignatureFormat.Rfc3279DerSequence);
            }
            else if (certificate.PublicKey.Oid.Value == Oids.Ed25519)
            {
                valid = signature.Length == 64;
            }
            else if (certificate.PublicKey.Oid.Value == Oids.Ed448)
            {
                valid = signature.Length == 114;
            }
            else
            {
                valid = false;
            }
        }

        if (!valid)
        {
            throw new SigningException(
                "External signer returned a signature that does not match the requested payload, algorithm, or encoding.",
                SigningErrorReason.AlgorithmIncompatible);
        }
    }

    private static void ValidateEcdsaDer(ReadOnlySpan<byte> signature)
    {
        try
        {
            var reader = new AsnReader(signature.ToArray(), AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            _ = sequence.ReadIntegerBytes();
            _ = sequence.ReadIntegerBytes();
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
        }
        catch (AsnContentException ex)
        {
            throw new SigningException(
                "External signer returned an invalid DER-encoded ECDSA signature.",
                SigningErrorReason.AlgorithmIncompatible,
                ex);
        }
    }
}
