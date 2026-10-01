using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>Collected LTV data for CAdES-B-LT embedding.</summary>
public sealed record LtvCollectionResult(
    IReadOnlyList<byte[]> CertificateRawData,
    IReadOnlyList<byte[]> OcspResponses,
    IReadOnlyList<byte[]> Crls,
    IReadOnlyList<LtvCertificateStatus>? CertificateStatuses = null)
{
    /// <summary>
    /// Whether every supplied non-self-signed certificate for which revocation data is required has
    /// applicable, authenticated and current OCSP or CRL evidence. At least one certificate
    /// must require revocation data. Newly discovered responder certificates are checked by
    /// completed-artifact validation after embedding.
    /// </summary>
    public bool HasCompleteRevocationData => CertificateStatuses is { Count: > 0 }
        && CertificateStatuses.Any(status => status.RequiresRevocationData)
        && CertificateStatuses
            .Where(status => status.RequiresRevocationData)
            .All(status => status.HasRevocationData);
}

/// <summary>Per-certificate revocation-material collection status.</summary>
public sealed record LtvCertificateStatus(
    string Thumbprint,
    bool RequiresRevocationData,
    bool HasRevocationData);

/// <summary>
/// Collects certificate and revocation data (OCSP responses and/or CRLs)
/// for embedding in CAdES-B-LT signatures.
/// </summary>
public static class LtvDataCollector
{
    /// <summary>
    /// Collects LTV data for the certificate chain.
    /// </summary>
    /// <param name="httpClient">HTTP client for network requests.</param>
    /// <param name="signerCert">The signer certificate.</param>
    /// <param name="chainCertificates">Optional intermediate certificates.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="ocspClient">Optional OCSP client for DI integration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collected certificate raw data, OCSP responses, and CRLs.</returns>
    public static async Task<LtvCollectionResult> CollectAsync(
        HttpClient httpClient,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chainCertificates,
        ILogger? logger,
        IOcspClient? ocspClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(signerCert);

        var allCerts = new List<X509Certificate2> { signerCert };
        if (chainCertificates is not null)
        {
            foreach (var cert in chainCertificates)
            {
                if (!allCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allCerts.Add(cert);
                }
            }
        }

        var ocspResponses = new List<byte[]>();
        var crls = new List<byte[]>();
        var extraResponderCerts = new List<X509Certificate2>();
        var certificateStatuses = new List<LtvCertificateStatus>();

        var ocsp = ocspClient ?? new OcspClient(httpClient, logger);

        foreach (var cert in allCerts)
        {
            var issuer = allCerts.FindIssuerOf(cert);
            bool requiresRevocationData = !cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData);
            bool hasRevocationData = false;

            // Try OCSP first (preferred per ETSI TS 119 172)
            string? ocspUrl = OcspClient.GetOcspUrl(cert);
            if (ocspUrl is not null)
            {
                try
                {
                    var result = await ocsp.FetchOcspResponseAsync(cert, issuer, ocspUrl, cancellationToken)
                        .ConfigureAwait(false);
                    if (!result.IsValid || result.ResponseBytes.Length == 0
                        || issuer is null
                        || !EmbeddedRevocationEvidence.CoversCertificate(
                            cert, issuer, [result.ResponseBytes], [], DateTimeOffset.UtcNow, ocsp))
                    {
                        throw new InvalidOperationException("OCSP response was not valid.");
                    }

                    ocspResponses.Add(result.ResponseBytes);
                    foreach (var rc in result.ResponderCertificates)
                    {
                        if (!allCerts.Any(c => c.Thumbprint == rc.Thumbprint))
                        {
                            extraResponderCerts.Add(rc);
                        }
                    }
                    hasRevocationData = true;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    // OCSP failed — fall back to CRL
                }
            }

            // Fallback: CRL
            if (!hasRevocationData)
            {
                string? crlUrl = CrlClient.GetCrlUrl(cert, logger);
                if (crlUrl is not null)
                {
                    try
                    {
                        var crlBytes = await ResilientHttp.GetBytesAsync(httpClient, crlUrl, logger: logger, ct: cancellationToken)
                            .ConfigureAwait(false);
                        if (crlBytes is not null && issuer is not null
                            && EmbeddedRevocationEvidence.CoversCertificate(
                                cert, issuer, [], [crlBytes], DateTimeOffset.UtcNow, ocsp))
                        {
                            crls.Add(crlBytes);
                            hasRevocationData = true;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch
                    {
                        // CRL also failed — skip; validation will be partial
                    }
                }
            }

            certificateStatuses.Add(new LtvCertificateStatus(
                cert.Thumbprint,
                requiresRevocationData,
                hasRevocationData));
        }

        var certs = new List<byte[]>();
        foreach (var cert in allCerts)
        {
            certs.Add(cert.RawData);
        }
        foreach (var cert in extraResponderCerts)
        {
            certs.Add(cert.RawData);
        }

        return new LtvCollectionResult(
            certs.AsReadOnly(),
            ocspResponses.AsReadOnly(),
            crls.AsReadOnly(),
            certificateStatuses.AsReadOnly());
    }
}
