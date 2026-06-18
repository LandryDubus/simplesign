using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.CAdES;

/// <summary>
/// Creates standalone CAdES digital signatures (ETSI EN 319 122) as detached
/// CMS/PKCS#7 SignedData — no PDF wrapper.
/// </summary>
public static class CadesSigner
{
    /// <summary>
    /// Signs the provided data and returns a DER-encoded CAdES signature.
    /// </summary>
    /// <param name="data">The original document bytes to sign.</param>
    /// <param name="certificate">Certificate with private key.</param>
    /// <param name="options">Optional signing configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>DER-encoded CMS/PKCS#7 SignedData (detached).</returns>
    public static async Task<byte[]> SignAsync(
        byte[] data,
        X509Certificate2 certificate,
        CadesSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key.", nameof(certificate));
        }

        options ??= new CadesSigningOptions();
        var log = logger ?? NullLogger.Instance;

        var signingTime = options.SigningTime ?? DateTimeOffset.UtcNow;
        var hashAlg = options.HashAlgorithm;
        string sigAlgOid = options.SignatureAlgorithmOid
            ?? DetectSignatureAlgorithmOid(certificate, hashAlg);

        var extraAttributes = BuildSignedAttributes(options);

        byte[] cms = CmsSignatureBuilder.Build(
            data, certificate, hashAlg, signingTime,
            options.ExtraCertificates, extraAttributes,
            padesAttributes: false,
            signatureAlgorithmOid: sigAlgOid,
            logger: log);

        // CAdES-B-T: apply timestamp
        if (options.Level >= CadesLevel.Timestamped && options.TsaUrl is not null)
        {
            cms = await ApplyTimestampAsync(cms, options, hashAlg, log, cancellationToken).ConfigureAwait(false);
        }

        // CAdES-B-LT: embed certificate and revocation values
        if (options.Level >= CadesLevel.LongTerm)
        {
            cms = await ApplyLtvAsync(cms, certificate, options, log, cancellationToken).ConfigureAwait(false);
        }

        // CAdES-B-LTA: embed archive timestamp
        if (options.Level >= CadesLevel.Archive && options.TsaUrl is not null)
        {
            cms = await ApplyArchiveTimestampAsync(cms, options, hashAlg, log, cancellationToken).ConfigureAwait(false);
        }

        return cms;
    }

    /// <summary>
    /// Signs the provided data using an external signing delegate.
    /// Use for HSMs, cloud KMS, or A3 tokens where the private key is not directly accessible.
    /// </summary>
    /// <param name="data">The original document bytes to sign.</param>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="externalSigner">Delegate that receives signed attributes and returns raw signature bytes.</param>
    /// <param name="signatureAlgorithmOid">OID of the signature algorithm used by the external signer.</param>
    /// <param name="options">Optional signing configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>DER-encoded CMS/PKCS#7 SignedData (detached).</returns>
    public static async Task<byte[]> SignAsync(
        byte[] data,
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner,
        string signatureAlgorithmOid,
        CadesSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);

        options ??= new CadesSigningOptions();
        var log = logger ?? NullLogger.Instance;

        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, signatureAlgorithmOid);

        var signingTime = options.SigningTime ?? DateTimeOffset.UtcNow;
        var hashAlg = options.HashAlgorithm;
        string digestOid = CmsSignatureBuilder.GetDigestOid(hashAlg);

        byte[] contentHash = CmsSignatureBuilder.ComputeHash(data, hashAlg);
        var extraAttributes = BuildSignedAttributes(options);

        byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
            contentHash, digestOid, signingTime, certificate, extraAttributes,
            padesAttributes: false);

        log.Log(LogLevel.Debug, "CAdES external signer invoked.");
        byte[] signature = await externalSigner(signedAttrs).ConfigureAwait(false);
        if (signature is null || signature.Length == 0)
        {
            throw new InvalidOperationException("External signer returned null or empty signature.");
        }

        List<X509Certificate2> allCerts = [certificate, .. (options.ExtraCertificates ?? [])];

        byte[] cms = CmsSignatureBuilder.BuildSignedData(
            digestOid, signatureAlgorithmOid, hashAlg, signedAttrs,
            signature, certificate, allCerts);

        // CAdES-B-T: apply timestamp
        if (options.Level >= CadesLevel.Timestamped && options.TsaUrl is not null)
        {
            cms = await ApplyTimestampAsync(cms, options, hashAlg, log, cancellationToken).ConfigureAwait(false);
        }

        // CAdES-B-LT: embed certificate and revocation values
        if (options.Level >= CadesLevel.LongTerm)
        {
            cms = await ApplyLtvAsync(cms, certificate, options, log, cancellationToken).ConfigureAwait(false);
        }

        // CAdES-B-LTA: embed archive timestamp
        if (options.Level >= CadesLevel.Archive && options.TsaUrl is not null)
        {
            cms = await ApplyArchiveTimestampAsync(cms, options, hashAlg, log, cancellationToken).ConfigureAwait(false);
        }

        return cms;
    }

    private static async Task<byte[]> ApplyTimestampAsync(
        byte[] cms, CadesSigningOptions options, HashAlgorithmName hashAlg,
        ILogger logger, CancellationToken ct)
    {
        var httpClient = options.TsaHttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        var tsaClient = new TimestampClient(httpClient, options.TsaUrl!, logger);
        byte[] tsToken = await tsaClient.GetTimestampAsync(
            TimestampClient.ExtractSignatureValue(cms), hashAlg, ct).ConfigureAwait(false);
        return TimestampClient.EmbedTimestampInCms(cms, tsToken);
    }

    private static async Task<byte[]> ApplyLtvAsync(
        byte[] cms, X509Certificate2 certificate, CadesSigningOptions options,
        ILogger logger, CancellationToken ct)
    {
        // Extract timestamp token (if present) to include TSA certs
        var cmsData = CmsParser.Parse(cms, logger);
        byte[]? timestampToken = cmsData?.SignatureTimestampToken;

        // Collect all known certs: signer + extra + TSA certs
        var allKnownCerts = new List<X509Certificate2> { certificate };
        if (options.ExtraCertificates is not null)
        {
            foreach (var cert in options.ExtraCertificates)
            {
                if (!allKnownCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allKnownCerts.Add(cert);
                }
            }
        }

        // Add TSA certificates from the timestamp token (if B-T was applied)
        if (timestampToken is not null)
        {
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(timestampToken);
            foreach (var cert in tsaCerts)
            {
                if (!allKnownCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allKnownCerts.Add(cert);
                }
            }
        }

        // Collect revocation data
        var httpClient = options.RevocationHttpClient
            ?? options.TsaHttpClient
            ?? DefaultHttpClientProvider.Instance.GetClient();

        var ltvData = await LtvDataCollector.CollectAsync(
            httpClient, certificate, allKnownCerts, logger, ct).ConfigureAwait(false);

        // Build unsigned attributes
        var unsignedAttrs = new List<CmsAttribute>();

        if (ltvData.CertificateRawData.Count > 0)
        {
            unsignedAttrs.Add(CmsAttribute.CertValues([.. ltvData.CertificateRawData]));
        }

        if (ltvData.OcspResponses.Count > 0 || ltvData.Crls.Count > 0)
        {
            unsignedAttrs.Add(CmsAttribute.RevocationValues(
                ltvData.OcspResponses.Count > 0 ? [.. ltvData.OcspResponses] : null,
                ltvData.Crls.Count > 0 ? [.. ltvData.Crls] : null));
        }

        if (unsignedAttrs.Count > 0)
        {
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, unsignedAttrs);
        }

        return cms;
    }

    private static async Task<byte[]> ApplyArchiveTimestampAsync(
        byte[] cms, CadesSigningOptions options, HashAlgorithmName hashAlg,
        ILogger logger, CancellationToken ct)
    {
        var httpClient = options.TsaHttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        var tsaClient = new TimestampClient(httpClient, options.TsaUrl!, logger);

        // Archive timestamp covers the entire CMS (including all unsigned attributes)
        byte[] cmsHash = ComputeCmsDigest(cms, hashAlg);
        byte[] tsToken = await tsaClient.GetTimestampAsync(cmsHash, hashAlg, ct).ConfigureAwait(false);

        // Embed as id-aa-ets-archiveTimeStampV3 (OID 2.48) unsigned attribute
        return CmsSignatureBuilder.AddUnsignedAttributes(cms,
        [
            CmsAttribute.Create(Oids.ArchiveTimeStamp, tsToken)
        ]);
    }

    private static byte[] ComputeCmsDigest(byte[] cms, HashAlgorithmName hashAlg)
    {
        return hashAlg.Name switch
        {
            nameof(HashAlgorithmName.SHA256) => SHA256.HashData(cms),
            nameof(HashAlgorithmName.SHA384) => SHA384.HashData(cms),
            nameof(HashAlgorithmName.SHA512) => SHA512.HashData(cms),
            nameof(HashAlgorithmName.SHA3_256) => SHA3_256.HashData(cms),
            nameof(HashAlgorithmName.SHA3_384) => SHA3_384.HashData(cms),
            nameof(HashAlgorithmName.SHA3_512) => SHA3_512.HashData(cms),
            _ => SHA256.HashData(cms)
        };
    }

    private static IReadOnlyList<CmsAttribute>? BuildSignedAttributes(CadesSigningOptions options)
    {
        var attrs = new List<CmsAttribute>();

        if (options.CommitmentType.HasValue)
        {
            attrs.Add(CmsAttribute.CommitmentTypeIndication(options.CommitmentType.Value));
        }

        if (options.SignaturePolicyOid is not null)
        {
            attrs.Add(CmsAttribute.SignaturePolicyIdentifier(
                options.SignaturePolicyOid, options.SignaturePolicyUri));
        }

        return attrs.Count > 0 ? attrs : null;
    }

    private static string DetectSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
    {
        string keyAlg = cert.PublicKey.Oid.Value ?? string.Empty;

        if (cert.PublicKey.Oid.Value == Oids.RsaPss || cert.SignatureAlgorithm.Value == Oids.RsaPss)
        {
            return Oids.RsaPss;
        }

        return (keyAlg, hashAlg) switch
        {
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.RsaSha256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.RsaSha384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.RsaSha512,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA3_256 => Oids.RsaSha3_256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA3_384 => Oids.RsaSha3_384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA3_512 => Oids.RsaSha3_512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.EcdsaSha256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.EcdsaSha384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.EcdsaSha512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA3_256 => Oids.EcdsaSha3_256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA3_384 => Oids.EcdsaSha3_384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA3_512 => Oids.EcdsaSha3_512,
            (Oids.Ed25519, _) => Oids.Ed25519,
            (Oids.Ed448, _) => Oids.Ed448,
            _ => throw new NotSupportedException(
                $"No signature OID for key '{cert.PublicKey.Oid.FriendlyName}' + hash '{hashAlg.Name}'.")
        };
    }
}
