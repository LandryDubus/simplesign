using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>Result of a CAdES signature validation.</summary>
public sealed class CadesValidationResult
{
    /// <summary>The cryptographic signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The document integrity is intact (content hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>The timestamp (if present) is valid.</summary>
    public bool? HasValidTimestamp { get; init; }

    /// <summary>Root SignedData evidence covers the embedded non-root certificate paths.</summary>
    public bool? IsLtvDataValid { get; init; }

    /// <summary>The archive timestamp (if present) is valid.</summary>
    public bool? HasValidArchiveTimestamp { get; init; }

    /// <summary>The signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>Signing time from the signed attributes.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>True when all checks pass.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && IsCertificateChainValid;
}

/// <summary>
/// Validates standalone CAdES digital signatures (ETSI EN 319 122).
/// Given a detached CMS/PKCS#7 SignedData and the original document,
/// verifies content integrity, cryptographic signature, certificate chain,
/// timestamp (if present), and LTV data (if present).
/// </summary>
public sealed class CadesSignatureValidator : ICadesSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly ILogger? _logger;
    private readonly ICryptoVerifier _cryptoVerifier;
    private readonly ICmsParser _cmsParser;
    private readonly ITimestampValidator _timestampValidator;

    /// <summary>Creates a validator with the specified options.</summary>
    public CadesSignatureValidator(
        ValidationOptions? options = null,
        ILogger? logger = null,
        ICryptoVerifier? cryptoVerifier = null,
        ICmsParser? cmsParser = null,
        ITimestampValidator? timestampValidator = null)
    {
        _options = options ?? new ValidationOptions();
        _logger = logger;
        _cryptoVerifier = cryptoVerifier ?? new CryptoVerifierService();
        _cmsParser = cmsParser ?? new CmsParserService();
        _timestampValidator = timestampValidator ?? new TimestampValidatorService();
    }

    /// <summary>
    /// Validates a CAdES detached signature.
    /// </summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="originalData">The original document bytes that were signed.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    /// <returns>A detailed validation result.</returns>
    public CadesValidationResult Validate(
        byte[] cmsBytes,
        byte[] originalData,
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        ArgumentNullException.ThrowIfNull(originalData);

        var errors = new List<string>();
        var warnings = new List<string>();

        // 1. Parse CMS
        CmsSignedData? cmsData;
        try
        {
            cmsData = _cmsParser.Parse(cmsBytes, _logger);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"Failed to parse CMS: {ex.Message}");
            return new CadesValidationResult { Errors = errors.AsReadOnly() };
        }

        if (cmsData.SignerCertificate is null)
        {
            errors.Add("No signer certificate found in CMS.");
        }

        if (cmsData.MessageDigest is null)
        {
            errors.Add("No messageDigest attribute found in signed attributes.");
        }

        if (errors.Count > 0)
        {
            return new CadesValidationResult { Errors = errors.AsReadOnly() };
        }

        // 2. Verify content integrity (hash match)
        bool integrityValid = VerifyContentHash(originalData, cmsData, errors);

        // 3. Verify cryptographic signature
        bool sigValid = _cryptoVerifier.VerifySignature(cmsData, _logger);
        if (!sigValid)
        {
            errors.Add("Cryptographic signature verification failed.");
        }

        // 4. Validate signingCertificateV2 binding
        if (cmsData.SigningCertificateHash is not null && cmsData.SignerCertificate is not null)
        {
            _cryptoVerifier.ValidateSigningCertV2(cmsData, errors, _logger);
        }

        // 5. Certificate chain validation
        bool chainValid = ValidateChain(cmsData.SignerCertificate!, cmsData.Certificates,
            errors, warnings, trustAnchors);

        // 6. Timestamp validation
        bool? tsValid = null;
        if (cmsData.SignatureTimestampToken is not null)
        {
            tsValid = _timestampValidator.Validate(cmsData, warnings, logger: _logger);
        }

        // 7. LTV data validation from root SignedData
        bool? ltvValid = ValidateLtvData(cmsBytes, cmsData, warnings);

        // 8. Archive timestamp validation
        bool? archiveTsValid = null;
        if (cmsData.ArchiveTimestampToken is not null)
        {
            archiveTsValid = ValidateArchiveTimestamp(cmsBytes, originalData, cmsData, warnings);
        }

        return new CadesValidationResult
        {
            IsSignatureValid = sigValid,
            IsIntegrityValid = integrityValid,
            IsCertificateChainValid = chainValid,
            HasValidTimestamp = tsValid,
            IsLtvDataValid = ltvValid,
            HasValidArchiveTimestamp = archiveTsValid,
            SignerCertificate = cmsData.SignerCertificate,
            SigningTime = cmsData.SigningTime,
            Errors = errors.AsReadOnly(),
            Warnings = warnings.Count > 0 ? warnings.AsReadOnly() : []
        };
    }

    private static bool VerifyContentHash(byte[] originalData, CmsSignedData cmsData, List<string> errors)
    {
        byte[] actualHash = cmsData.DigestAlgorithmOid switch
        {
            Oids.Sha256 => SHA256.HashData(originalData),
            Oids.Sha384 => SHA384.HashData(originalData),
            Oids.Sha512 => SHA512.HashData(originalData),
            Oids.Sha3_256 => SHA3_256.HashData(originalData),
            Oids.Sha3_384 => SHA3_384.HashData(originalData),
            Oids.Sha3_512 => SHA3_512.HashData(originalData),
            _ => SHA256.HashData(originalData)
        };

        bool valid = actualHash.AsSpan().SequenceEqual(cmsData.MessageDigest!);
        if (!valid)
        {
            errors.Add("Content hash mismatch — the document has been altered since signing.");
        }

        return valid;
    }

    private bool ValidateChain(
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2> embeddedCertificates,
        List<string> errors,
        List<string> warnings,
        IEnumerable<X509Certificate2>? trustAnchors)
    {
        try
        {
            bool hasCustomRoots = trustAnchors is not null
                || (_options.TrustedRoots is { Count: > 0 })
                || !_options.TrustSystemRoots;

            using var chain = new X509Chain();
            CryptoUtility.ConfigureChainPolicy(chain, _options.CheckRevocation);
            foreach (var embedded in embeddedCertificates)
            {
                if (!embedded.RawData.AsSpan().SequenceEqual(signerCert.RawData))
                {
                    chain.ChainPolicy.ExtraStore.Add(embedded);
                }
            }

            if (hasCustomRoots)
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationFlags =
                    X509VerificationFlags.IgnoreEndRevocationUnknown |
                    X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;

                AddTrustAnchors(chain, trustAnchors);
                AddTrustAnchors(chain, _options.TrustedRoots);
            }

            bool built = chain.Build(signerCert);

            foreach (var element in chain.ChainElements)
            {
                foreach (var status in element.ChainElementStatus)
                {
                    string msg = $"{status.Status}: {status.StatusInformation}".TrimEnd('.');
                    if (status.Status is X509ChainStatusFlags.RevocationStatusUnknown
                        or X509ChainStatusFlags.OfflineRevocation)
                    {
                        warnings.Add(msg);
                    }
                    else if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        errors.Add(msg);
                    }
                }
            }

            return built;
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"Chain validation error: {ex.Message}");
            return false;
        }
    }

    private static void AddTrustAnchors(X509Chain chain, IEnumerable<X509Certificate2>? anchors)
    {
        if (anchors is null)
        {
            return;
        }

        foreach (var cert in anchors)
        {
            if (cert.IsSelfSigned())
            {
                chain.ChainPolicy.CustomTrustStore.Add(cert);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }
    }

    private static bool? ValidateLtvData(byte[] cmsBytes, CmsSignedData cmsData, List<string> warnings)
    {
        if (cmsData.UnsignedAttributes is not null
            && (cmsData.UnsignedAttributes.ContainsKey(Oids.CertValues)
                || cmsData.UnsignedAttributes.ContainsKey(Oids.RevocationValues)))
        {
            warnings.Add("CAdES-B-LT: Legacy certificate-values/revocation-values attributes are not permitted by the baseline profile.");
            return false;
        }
        try
        {
            var reader = new AsnReader(cmsBytes, AsnEncodingRules.BER);
            var contentInfo = reader.ReadSequence();
            _ = contentInfo.ReadObjectIdentifier();
            var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            var signedData = wrapper.ReadSequence();
            _ = signedData.ReadEncodedValue();
            _ = signedData.ReadEncodedValue();
            _ = signedData.ReadEncodedValue();
            if (signedData.HasData
                && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                _ = signedData.ReadEncodedValue();
            }
            if (!signedData.HasData
                || signedData.PeekTag() != new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                return null;
            }
            var revocations = signedData.ReadSetOf(skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 1, true));
            if (!revocations.HasData || cmsData.Certificates.Count == 0)
            {
                warnings.Add("CAdES-B-LT: Root SignedData lacks certificates or revocation values.");
                return false;
            }
            if (cmsData.SignerCertificate is null
                || !cmsData.Certificates.Any(cert =>
                    cert.RawData.AsSpan().SequenceEqual(cmsData.SignerCertificate.RawData)))
            {
                warnings.Add("CAdES-B-LT: Root SignedData does not include the signer certificate.");
                return false;
            }

            foreach (var token in new[] { cmsData.SignatureTimestampToken, cmsData.ArchiveTimestampToken })
            {
                if (token is null)
                {
                    continue;
                }

                var tsaCertificates = TsaCertificateExtractor.ExtractCertificates(token);
                try
                {
                    if (!tsaCertificates.All(tsa => cmsData.Certificates.Any(cert =>
                        cert.RawData.AsSpan().SequenceEqual(tsa.RawData))))
                    {
                        warnings.Add("CAdES-B-LT: Root SignedData does not include the timestamp certificates.");
                        return false;
                    }
                }
                finally
                {
                    foreach (var tsaCertificate in tsaCertificates)
                    {
                        tsaCertificate.Dispose();
                    }
                }
            }
            var crls = new List<byte[]>();
            var ocsps = new List<byte[]>();
            while (revocations.HasData)
            {
                if (revocations.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
                {
                    var other = revocations.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                    string oid = other.ReadObjectIdentifier();
                    if (oid == "1.3.6.1.5.5.7.16.2")
                    {
                        ocsps.Add(other.ReadEncodedValue().ToArray());
                    }
                }
                else
                {
                    crls.Add(revocations.ReadEncodedValue().ToArray());
                }
            }

            using var httpClient = new HttpClient();
            bool covered = EmbeddedRevocationEvidence.CoversAll(
                cmsData.Certificates, ocsps, crls,
                cmsData.SigningTime ?? DateTimeOffset.UtcNow,
                new OcspClient(httpClient));
            if (!covered)
            {
                warnings.Add("CAdES-B-LT: Revocation evidence does not cover every non-root certificate.");
            }

            return covered;
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LT: Failed to parse root validation material: {ex.Message}");
            return false;
        }
    }

    private static bool ValidateArchiveTimestamp(
        byte[] cmsBytes, byte[] originalData, CmsSignedData cmsData, List<string> warnings)
    {
        byte[]? archiveToken = cmsData.ArchiveTimestampToken;
        if (archiveToken is null)
        {
            warnings.Add("CAdES-B-LTA: No archive timestamp token found.");
            return false;
        }

        try
        {
            var parsedToken = CmsParser.Parse(archiveToken);
            if (parsedToken?.UnsignedAttributes is null
                || !parsedToken.UnsignedAttributes.TryGetValue(Oids.AtsHashIndexV3, out var indexValues)
                || indexValues.Length != 1)
            {
                warnings.Add("CAdES-B-LTA: Archive timestamp has no single ATSHashIndexV3 value.");
                return false;
            }
            HashAlgorithmName hashAlgorithm = parsedToken.TstMessageImprintHashAlgOid switch
            {
                Oids.Sha256 => HashAlgorithmName.SHA256,
                Oids.Sha384 => HashAlgorithmName.SHA384,
                Oids.Sha512 => HashAlgorithmName.SHA512,
                Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
                Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
                Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
                _ => throw new NotSupportedException("Unsupported archive timestamp hash algorithm.")
            };
            var input = CadesArchiveTimestampBuilder.Build(
                cmsBytes, originalData, hashAlgorithm, excludeArchiveTimestamp: true);
            if (!input.AtsHashIndex.AsSpan().SequenceEqual(indexValues[0]))
            {
                warnings.Add("CAdES-B-LTA: ATSHashIndexV3 does not cover the signature material.");
                return false;
            }
            return TimestampValidator.Validate(archiveToken, input.DataToTimestamp,
                cmsData.SigningTime, warnings) == true;
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LTA: Failed to validate archive timestamp: {ex.Message}");
            return false;
        }
    }
}
