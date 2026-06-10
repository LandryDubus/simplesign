using System.Formats.Asn1;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Represents a pre-encoded CMS signed attribute (OID + DER value).
/// Used to inject custom CAdES attributes into the CMS SignedData.
/// </summary>
public sealed class CmsAttribute
{
    /// <summary>The OID of the attribute.</summary>
    public string Oid { get; }

    /// <summary>The DER-encoded value (the content of SET OF { value }).</summary>
    public byte[] DerValue { get; }

    private CmsAttribute(string oid, byte[] derValue)
    {
        Oid = oid;
        DerValue = derValue;
    }

    /// <summary>
    /// Creates a commitment-type-indication attribute (RFC 5126 §5.11.1).
    /// <code>
    /// CommitmentTypeIndication ::= SEQUENCE {
    ///   commitmentTypeId  CommitmentTypeIdentifier }
    /// CommitmentTypeIdentifier ::= OID
    /// </code>
    /// </summary>
    public static CmsAttribute CommitmentTypeIndication(CommitmentType type)
    {
        string typeOid = type switch
        {
            CommitmentType.ProofOfOrigin => Oids.ProofOfOrigin,
            CommitmentType.ProofOfApproval => Oids.ProofOfApproval,
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CommitmentTypeIndication
        {
            writer.WriteObjectIdentifier(typeOid);
        }

        return new CmsAttribute(Oids.CommitmentTypeIndication, writer.Encode());
    }

    /// <summary>
    /// Creates a signature-policy-identifier attribute (RFC 5126 §5.8.1).
    /// <code>
    /// SignaturePolicyIdentifier ::= SEQUENCE {
    ///   signaturePolicyId    SignaturePolicyId,
    ///   sigPolicyHash        SigPolicyHash OPTIONAL }
    /// SignaturePolicyId ::= OID
    /// SigPolicyHash ::= OtherHashAlgAndValue (SEQUENCE { algorithm, hash })
    /// </code>
    /// </summary>
    /// <param name="policyOid">OID of the signature policy.</param>
    /// <param name="policyUri">Optional URI of the policy document (encoded as SigPolicyQualifier).</param>
    public static CmsAttribute SignaturePolicyIdentifier(string policyOid, string? policyUri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyOid);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // SignaturePolicyIdentifier
        {
            // signaturePolicyId
            writer.WriteObjectIdentifier(policyOid);

            // sigPolicyHash — empty hash (policy hash is optional for org-defined policies)
            using (writer.PushSequence()) // OtherHashAlgAndValue
            {
                using (writer.PushSequence()) // AlgorithmIdentifier
                {
                    writer.WriteObjectIdentifier(Oids.Sha256);
                    writer.WriteNull();
                }
                writer.WriteOctetString([]); // empty hash — not computed for org policies
            }

            // sigPolicyQualifiers OPTIONAL
            if (!string.IsNullOrEmpty(policyUri))
            {
                using (writer.PushSequence()) // SEQUENCE OF SigPolicyQualifierInfo
                {
                    using (writer.PushSequence()) // SigPolicyQualifierInfo
                    {
                        // id-spq-ets-uri (1.2.840.113549.1.9.16.5.1)
                        writer.WriteObjectIdentifier("1.2.840.113549.1.9.16.5.1");
                        writer.WriteCharacterString(UniversalTagNumber.IA5String, policyUri);
                    }
                }
            }
        }

        return new CmsAttribute(Oids.SignaturePolicyIdentifier, writer.Encode());
    }

    /// <summary>
    /// Creates a CmsAttribute from raw OID and DER-encoded value.
    /// </summary>
    public static CmsAttribute Raw(string oid, byte[] derValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        ArgumentNullException.ThrowIfNull(derValue);
        return new CmsAttribute(oid, derValue);
    }

    /// <summary>
    /// Creates a signature manifest attribute containing JSON-encoded evidence.
    /// The data is embedded as an OCTET STRING (UTF-8 JSON) under OID 2.16.76.1.12.1.1.
    /// </summary>
    /// <param name="manifestJsonUtf8">UTF-8 encoded JSON bytes of the manifest.</param>
    public static CmsAttribute SignatureManifestAttr(byte[] manifestJsonUtf8)
    {
        ArgumentNullException.ThrowIfNull(manifestJsonUtf8);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(manifestJsonUtf8);

        return new CmsAttribute(Oids.SignatureManifest, writer.Encode());
    }

    /// <summary>
    /// Creates a certificate-refs attribute (CAdES-X/L, RFC 5126 §5.4.2).
    /// <code>
    /// CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
    /// OtherCertID ::= OtherHash { issuerSerial OPTIONAL }
    /// </code>
    /// </summary>
    /// <param name="certHashes">Array of (certHash, hashAlgorithmOid, issuerSerialBytes) tuples.</param>
    public static CmsAttribute CertificateRefs(params (byte[] Hash, string HashOid, byte[]? IssuerSerial)[] certHashes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CompleteCertificateRefs
        {
            foreach (var (hash, hashOid, issuerSerial) in certHashes)
            {
                using (writer.PushSequence()) // OtherCertID
                {
                    using (writer.PushSequence()) // OtherHashAlgAndValue
                    {
                        using (writer.PushSequence()) // AlgorithmIdentifier
                        {
                            writer.WriteObjectIdentifier(hashOid);
                            writer.WriteNull();
                        }
                        writer.WriteOctetString(hash);
                    }
                    if (issuerSerial is not null)
                    {
                        writer.WriteEncodedValue(issuerSerial);
                    }
                }
            }
        }
        return new CmsAttribute(Oids.CertificateRefs, writer.Encode());
    }

    /// <summary>
    /// Creates a revocation-refs attribute (CAdES-X/L, RFC 5126 §5.4.3).
    /// </summary>
    /// <param name="crlDerBytes">Array of DER-encoded CRL bytes.</param>
    public static CmsAttribute RevocationRefs(params byte[][] crlDerBytes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CompleteRevocationRefs
        {
            foreach (var crl in crlDerBytes)
            {
                using (writer.PushSequence()) // CrlIdentifier (simplified: just the CRL bytes)
                {
                    writer.WriteEncodedValue(crl);
                }
            }
        }
        return new CmsAttribute(Oids.RevocationRefs, writer.Encode());
    }

    /// <summary>
    /// Creates a cert-values attribute (CAdES-XL, RFC 5126 §5.5.1).
    /// Embeds the full DER-encoded signer and CA certificates.
    /// </summary>
    /// <param name="certDerBytes">DER-encoded certificates.</param>
    public static CmsAttribute CertValues(params byte[][] certDerBytes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CertificateValues
        {
            foreach (var certDer in certDerBytes)
            {
                writer.WriteEncodedValue(certDer);
            }
        }
        return new CmsAttribute(Oids.CertValues, writer.Encode());
    }

    /// <summary>
    /// Creates a revocation-values attribute (CAdES-XL, RFC 5126 §5.5.2).
    /// Embeds CRLs and/or OCSP responses.
    /// </summary>
    /// <param name="ocspDerResponses">DER-encoded OCSP responses.</param>
    /// <param name="crlDerBytes">DER-encoded CRLs.</param>
    public static CmsAttribute RevocationValues(
        byte[][]? ocspDerResponses = null,
        byte[][]? crlDerBytes = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // RevocationValues
        {
            // revocationValues CHOICE { crlVals, ocspVals, ... }
            if (crlDerBytes is { Length: > 0 })
            {
                using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                    System.Formats.Asn1.TagClass.ContextSpecific, 0, true))) // crlVals [0]
                {
                    foreach (var crl in crlDerBytes)
                    {
                        writer.WriteEncodedValue(crl);
                    }
                }
            }
            if (ocspDerResponses is { Length: > 0 })
            {
                using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                    System.Formats.Asn1.TagClass.ContextSpecific, 1, true))) // ocspVals [1]
                {
                    foreach (var ocsp in ocspDerResponses)
                    {
                        writer.WriteEncodedValue(ocsp);
                    }
                }
            }
        }
        return new CmsAttribute(Oids.RevocationValues, writer.Encode());
    }
}
