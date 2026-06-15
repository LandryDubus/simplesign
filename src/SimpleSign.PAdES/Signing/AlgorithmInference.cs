using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Shared algorithm-inference logic for all signing paths (local, external, deferred).
/// Resolves the effective hash algorithm from the certificate when the user has not
/// explicitly set one, implementing:
///   - PSS cert's <c>RSASSA-PSS-params</c> (RFC 4055 §3.1) honoured.
///   - RSA key-size-based hash selection per NIST SP 800-57 Part 1 Rev. 5.
/// </summary>
internal static class AlgorithmInference
{
    /// <summary>
    /// Resolves the effective hash algorithm for a signing operation.
    /// </summary>
    /// <param name="cert">The signer's certificate.</param>
    /// <param name="hashAlgorithm">The hash algorithm chosen by the user (or the default SHA-256).</param>
    /// <param name="hashAlgorithmExplicitlySet">
    /// <see langword="true"/> if the user explicitly called <c>WithHashAlgorithm()</c>;
    /// <see langword="false"/> if the hash is still the library default.
    /// </param>
    /// <param name="signatureAlgorithmOid">
    /// Optional explicit signature algorithm OID (e.g. from <c>WithExternalSigner</c>).
    /// When provided and <paramref name="hashAlgorithmExplicitlySet"/> is <see langword="false"/>,
    /// the hash is inferred from the OID before falling back to certificate-based inference.
    /// </param>
    /// <returns>The effective hash algorithm to use for signing.</returns>
    internal static HashAlgorithmName ResolveEffectiveHashAlgorithm(
        X509Certificate2 cert,
        HashAlgorithmName hashAlgorithm,
        bool hashAlgorithmExplicitlySet,
        string? signatureAlgorithmOid = null)
    {
        if (hashAlgorithmExplicitlySet)
        {
            return hashAlgorithm;
        }

        // If the caller provided an explicit signature algorithm OID (e.g. via WithExternalSigner),
        // infer the hash from it. This ensures the CMS digestAlgorithm matches what the
        // external signer uses (e.g. RS512 → SHA512, not SHA256 from key-size heuristic).
        if (signatureAlgorithmOid is not null)
        {
            var hashFromOid = TryInferHashFromSignatureOid(signatureAlgorithmOid);
            if (hashFromOid is not null)
            {
                return hashFromOid.Value;
            }
        }

        // PSS cert — read hash from RSASSA-PSS-params.
        // Check SubjectPublicKeyInfo OID first (RFC 4055 §4), fall back to signature
        // algorithm for self-signed PSS certs.
        if (cert.PublicKey.Oid.Value == Oids.RsaPss || cert.SignatureAlgorithm.Value == Oids.RsaPss)
        {
            ReadOnlySpan<byte> pssParams = cert.PublicKey.Oid.Value == Oids.RsaPss
                ? ExtractPssParamsFromSpki(cert)
                : ExtractPssParamsFromCert(cert);
            return CryptoUtility.ParsePssHashAlgorithm(pssParams);
        }

        // RSA PKCS#1 cert — select hash based on key size.
        string keyOid = cert.PublicKey.Oid.Value ?? string.Empty;
        if (keyOid == Oids.RsaEncryption)
        {
            return SelectHashForRsaKeySize(cert);
        }

        // ECDSA, EdDSA, or unknown — keep the default (SHA-256).
        return hashAlgorithm;
    }

    /// <summary>
    /// Infers the hash algorithm from a signature algorithm OID when the hash is unambiguously
    /// encoded in the OID (RSA PKCS#1 and ECDSA combined-hash OIDs).
    /// Returns <see langword="null"/> for OIDs that do not encode a specific hash
    /// (e.g. <c>id-RSASSA-PSS</c> 1.2.840.113549.1.1.10), since those require
    /// out-of-band parameters.
    /// </summary>
    internal static HashAlgorithmName? TryInferHashFromSignatureOid(string sigOid) => sigOid switch
    {
        Oids.RsaSha256 or Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
        Oids.RsaSha384 or Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
        Oids.RsaSha512 or Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
        Oids.RsaSha1 => HashAlgorithmName.SHA1,
        _ => null,
    };

    /// <summary>
    /// Selects the appropriate hash algorithm based on the RSA key size,
    /// per NIST SP 800-57 Part 1 Rev. 5, Table 2.
    /// </summary>
    private static HashAlgorithmName SelectHashForRsaKeySize(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is not null && rsa.KeySize >= 3072)
            {
                return HashAlgorithmName.SHA384;
            }
        }
        catch (CryptographicException)
        {
            // Fall back to SHA-256 — a safe, conservative choice.
        }

        return HashAlgorithmName.SHA256;
    }

    /// <summary>
    /// Extracts the <c>RSASSA-PSS-params</c> bytes from a certificate whose
    /// <c>SignatureAlgorithm</c> is <c>id-RSASSA-PSS</c>. The params are the
    /// second element of the outer <c>AlgorithmIdentifier SEQUENCE</c> in the
    /// certificate's TBS signature algorithm field.
    /// </summary>
    /// <remarks>
    /// <c>X509Certificate2.SignatureAlgorithm</c> only exposes the OID, not the params.
    /// We must parse the raw TBS data to extract them. The approach reads the
    /// certificate's DER-encoded <c>RawData</c>, locates the TBS
    /// <c>signatureAlgorithm</c> field (which is the second-to-last SEQUENCE element
    /// in TBSCertificate), and extracts the parameters from it.
    /// </remarks>
    private static ReadOnlySpan<byte> ExtractPssParamsFromCert(X509Certificate2 cert)
    {
        try
        {
            // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
            // TBSCertificate ::= SEQUENCE { version [0], serialNumber, signature AlgId, ... }
            // The signature AlgId in TBS is at index 2 (after version [0] and serialNumber).
            var certReader = new AsnReader(cert.RawData, AsnEncodingRules.DER);
            var certSeq = certReader.ReadSequence();
            var tbsSeq = certSeq.ReadSequence();

            // version [0] EXPLICIT — skip
            if (tbsSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                tbsSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            }

            // serialNumber — skip
            tbsSeq.ReadInteger();

            // signature AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
            var algIdSeq = tbsSeq.ReadSequence();
            algIdSeq.ReadObjectIdentifier(); // skip OID (we already know it's id-RSASSA-PSS)

            if (algIdSeq.HasData)
            {
                return algIdSeq.ReadEncodedValue().Span;
            }
        }
        catch (AsnContentException)
        {
            // Malformed cert — fall through to empty params → ParsePssHashAlgorithm returns SHA-256
        }

        return default;
    }

    /// <summary>
    /// Extracts the <c>RSASSA-PSS-params</c> bytes from a certificate whose
    /// <c>SubjectPublicKeyInfo</c> algorithm OID is <c>id-RSASSA-PSS</c>
    /// (RFC 4055 §4). The params are the optional parameters element of the
    /// <c>AlgorithmIdentifier</c> inside the SPKI.
    /// </summary>
    private static ReadOnlySpan<byte> ExtractPssParamsFromSpki(X509Certificate2 cert)
    {
        try
        {
            // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
            var certReader = new AsnReader(cert.RawData, AsnEncodingRules.DER);
            var certSeq = certReader.ReadSequence();
            var tbsSeq = certSeq.ReadSequence();

            // version [0] EXPLICIT — skip
            if (tbsSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                tbsSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            }

            // serialNumber — skip
            tbsSeq.ReadInteger();

            // signature AlgorithmIdentifier — skip
            tbsSeq.ReadSequence();

            // issuer — skip
            tbsSeq.ReadSequence();

            // validity — skip
            tbsSeq.ReadSequence();

            // subject — skip
            tbsSeq.ReadSequence();

            // subjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
            var spkiSeq = tbsSeq.ReadSequence();
            var algIdSeq = spkiSeq.ReadSequence();
            algIdSeq.ReadObjectIdentifier(); // skip OID (we know it's id-RSASSA-PSS)

            if (algIdSeq.HasData)
            {
                return algIdSeq.ReadEncodedValue().Span;
            }
        }
        catch (AsnContentException)
        {
            // Malformed cert — fall through to empty params → ParsePssHashAlgorithm returns SHA-256
        }

        return default;
    }
}
