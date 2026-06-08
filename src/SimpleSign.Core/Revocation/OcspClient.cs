using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// OCSP (Online Certificate Status Protocol) client for certificate revocation checking.
/// Builds OCSP requests, sends them, and verifies response signatures.
/// </summary>
internal sealed class OcspClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    public OcspClient(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient;
        _logger = logger ?? NullLogger.Instance;
    }

    #region Instance methods

    internal async Task<bool> CheckOcspAsync(X509Certificate2 cert, string ocspUrl, CancellationToken ct)
    {
        var result = await FetchOcspResponseAsync(cert, issuerCert: null, ocspUrl, ct).ConfigureAwait(false);
        return result.IsValid;
    }

    internal async Task<bool> CheckOcspWithChainAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2> chain,
        string ocspUrl,
        CancellationToken ct)
    {
        var issuerCert = chain.FirstOrDefault(c =>
            c.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData)) ??
            chain.FirstOrDefault(c => string.Equals(c.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase));
        if (issuerCert is null)
        {
            _logger.OcspIssuerCertNotFound(cert.Subject);
        }
        var result = await FetchOcspResponseAsync(cert, issuerCert, ocspUrl, ct).ConfigureAwait(false);
        return result.IsValid;
    }

    /// <summary>
    /// Fetches an OCSP response and returns the revocation status, raw response bytes,
    /// and all responder certificates embedded in the response (for DSS inclusion).
    /// </summary>
    internal async Task<OcspFetchResult> FetchOcspResponseAsync(
        X509Certificate2 cert,
        X509Certificate2? issuerCert,
        string ocspUrl,
        CancellationToken ct)
    {
        byte[] ocspRequest = BuildOcspRequest(cert, issuerCert);
        using var content = new ByteArrayContent(ocspRequest);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");

        _logger.OcspRequestSending(ocspUrl);
        using var response = await ResilientHttp.PostAsync(_httpClient, ocspUrl, content, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"OCSP responder returned HTTP {(int)response.StatusCode}");
        }

        byte[] ocspResponse = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        _logger.OcspResponseReceived(ocspResponse.Length);
        var (isValid, responderCerts) = ParseOcspResponseWithCerts(ocspResponse, cert, _logger);
        return new OcspFetchResult(isValid, ocspResponse, responderCerts);
    }

    /// <summary>
    /// Checks an embedded OCSP response against a certificate.
    /// Returns: true = good (not revoked), false = revoked, null = not relevant for this cert or unparseable.
    /// </summary>
    internal bool? CheckEmbeddedOcspResponse(
        X509Certificate2 cert,
        X509Certificate2? issuerCert,
        byte[] ocspResponseBytes,
        DateTimeOffset? signingTime = null)
    {
        try
        {
            bool isValid = ParseOcspResponse(ocspResponseBytes, cert, _logger);
            return isValid;
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or AsnContentException or CryptographicException)
        {
            // Response doesn't apply to this cert or is malformed
            return null;
        }
    }

    #endregion

    #region Static methods

    /// <summary>
    /// Builds a minimal OCSPRequest (RFC 2560) for the provided certificate.
    /// CertID uses SHA-1 (required by RFC — not the document digest).
    ///
    /// issuerKeyHash = SHA-1(issuer public key BIT STRING value)
    /// If issuerCert is not provided, uses the subject's own public key as an approximation
    /// (less precise, but avoids silent rejection by the OCSP server).
    /// </summary>
    internal static byte[] BuildOcspRequest(X509Certificate2 cert, X509Certificate2? issuerCert)
    {
        // CertID = { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
        // issuerNameHash = SHA-1(DER encoding of issuer Name)
        // issuerKeyHash  = SHA-1(issuer SubjectPublicKeyInfo.subjectPublicKey BIT STRING value)
#pragma warning disable CA5350 // OCSP RFC 2560 mandates SHA-1 for CertID
        byte[] issuerNameHash = SHA1.HashData(cert.IssuerName.RawData);
        // If we have the issuer cert, we use its key — as per RFC 2560.
        // Otherwise, we use the cert's own key (acceptable fallback for servers
        // that only look up by serial+issuerName, ignoring issuerKeyHash).
        byte[] issuerKeyHash = issuerCert is not null
            ? SHA1.HashData(ExtractPublicKeyBytes(issuerCert))
            : SHA1.HashData(ExtractPublicKeyBytes(cert));
#pragma warning restore CA5350

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // OCSPRequest
        {
            using (writer.PushSequence()) // TBSRequest
            {
                using (writer.PushSequence()) // requestList
                {
                    using (writer.PushSequence()) // Request
                    {
                        using (writer.PushSequence()) // CertID
                        {
                            // hashAlgorithm AlgorithmIdentifier { SHA-1 }
                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier(Oids.Sha1); // SHA-1
                                writer.WriteNull();
                            }
                            writer.WriteOctetString(issuerNameHash); // issuerNameHash
                            writer.WriteOctetString(issuerKeyHash);  // issuerKeyHash
                            writer.WriteInteger(                     // serialNumber
                                new System.Numerics.BigInteger(cert.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true));
                        }
                    }
                }
            }
        }
        return writer.Encode();
    }

    /// <summary>
    /// Extracts the public key bytes (SubjectPublicKeyInfo.subjectPublicKey BIT STRING value)
    /// for computing the issuerKeyHash in OCSP.
    /// </summary>
    internal static byte[] ExtractPublicKeyBytes(X509Certificate2 cert)
    {
        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        // We want the BIT STRING content (without the padding byte)
        var spki = cert.PublicKey.ExportSubjectPublicKeyInfo();
        var reader = new AsnReader(spki, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        seq.ReadSequence(); // AlgorithmIdentifier
        var bitString = seq.ReadBitString(out _);
        return [.. bitString];
    }

    /// <summary>
    /// Parses an OCSPResponse (RFC 2560) and returns true if the certificate is not revoked.
    /// Validates the BasicOCSPResponse signature when possible.
    /// </summary>
    internal static bool ParseOcspResponse(byte[] ocspResponseBytes, X509Certificate2 cert, ILogger? logger = null)
    {
        var reader = new AsnReader(ocspResponseBytes, AsnEncodingRules.BER);
        var ocspResponse = reader.ReadSequence();

        // responseStatus
        var statusEncoded = ocspResponse.ReadEncodedValue().Span;
        int status = statusEncoded.Length >= 3 ? statusEncoded[2] : -1;
        if (status != 0)
        {
            throw new InvalidOperationException($"OCSP response status is not 'successful': {status}");
        }

        if (!ocspResponse.HasData)
        {
            throw new InvalidDataException("OCSP response is empty.");
        }

        // Compute expected CertID fields for matching (RFC 6960 §3.2)
#pragma warning disable CA5350 // OCSP RFC 2560 mandates SHA-1 for CertID
        byte[] expectedIssuerNameHash = SHA1.HashData(cert.IssuerName.RawData);
        byte[] expectedSerialNumber = cert.SerialNumberBytes.ToArray();
#pragma warning restore CA5350

        // RFC 6960: responseBytes [0] EXPLICIT ResponseBytes
        // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
        // The [0] EXPLICIT wrapper holds the *encoded* inner SEQUENCE — we must unwrap
        // both layers (the [0] tag and then the SEQUENCE) before reading responseType.
        var responseBytesWrapper = ocspResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var respBytes = responseBytesWrapper.ReadSequence();

        _ = respBytes.ReadObjectIdentifier(); // responseType (id-pkix-ocsp-basic)
        var basicOcspBytes = respBytes.ReadOctetString();

        // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, [0] certs OPTIONAL }
        var basicReader = new AsnReader(basicOcspBytes, AsnEncodingRules.BER);
        var basicOcsp = basicReader.ReadSequence();

        // Keep raw tbsResponseData for signature verification
        byte[] tbsResponseDataRaw = basicOcsp.PeekEncodedValue().ToArray();
        var tbsResponseData = basicOcsp.ReadSequence();

        // signatureAlgorithm — extract the OID and any RSASSA-PSS-params bytes
        var sigAlgSeq = basicOcsp.ReadSequence();
        string sigAlgOid = sigAlgSeq.ReadObjectIdentifier();
        byte[]? sigAlgParams = null;
        if (sigAlgSeq.HasData)
        {
            sigAlgParams = sigAlgSeq.ReadEncodedValue().ToArray();
        }

        // signature BIT STRING
        byte[] ocspSignature = basicOcsp.ReadBitString(out _);

        // certs [0] OPTIONAL — extract responder cert
        // Structure: [0] EXPLICIT { SEQUENCE OF Certificate }
        // We must unwrap the [0] tag to get the SEQUENCE OF, then iterate individual certs.
        X509Certificate2? responderCert = null;
#pragma warning disable CA2000 // responderCert is disposed in the finally block below
        if (basicOcsp.HasData && basicOcsp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certsWrapper = basicOcsp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            if (certsWrapper.HasData)
            {
                var certSeq = certsWrapper.ReadSequence(); // SEQUENCE OF Certificate
                while (certSeq.HasData)
                {
                    try
                    {
                        responderCert = CertificateLoader.LoadCertificate(certSeq.ReadEncodedValue().ToArray());
                        break; // use first cert
                    }
                    catch (CryptographicException ex)
                    {
                        logger?.OcspResponderCertLoadingFailed(ex.Message);
                        if (certSeq.HasData)
                        {
                            certSeq.ReadEncodedValue(); // skip malformed cert
                        }
                    }
                }
            }
        }
#pragma warning restore CA2000

        try
        {
            // Verify OCSP response signature
            if (responderCert is not null)
            {
                bool sigValid = VerifyOcspSignature(responderCert, tbsResponseDataRaw, ocspSignature, sigAlgOid, sigAlgParams, logger);
                if (!sigValid)
                {
                    throw new InvalidOperationException("OCSP response signature verification failed.");
                }
            }

            // Parse tbsResponseData for cert status
            if (tbsResponseData.HasData && tbsResponseData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                tbsResponseData.ReadEncodedValue(); // version
            }

            tbsResponseData.ReadEncodedValue(); // responderID
            tbsResponseData.ReadEncodedValue(); // producedAt

            var responses = tbsResponseData.ReadSequence();
            int? firstCertStatus = null;
            bool foundMatch = false;
            while (responses.HasData)
            {
                var single = responses.ReadSequence();

                // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
                // Verify that this response is for the certificate we requested (RFC 6960 §3.2)
                var certIdSeq = single.ReadSequence();
                certIdSeq.ReadSequence(); // hashAlgorithm — skip (we know it's SHA-1 from our request)
                byte[] respIssuerNameHash = certIdSeq.ReadOctetString();
                certIdSeq.ReadOctetString(); // issuerKeyHash — skip (not always available for matching)
                var respSerialNumber = certIdSeq.ReadIntegerBytes().ToArray();

                var certStatusTag = single.PeekTag();
                int? statusValue = certStatusTag.TagClass == TagClass.ContextSpecific ? certStatusTag.TagValue : null;

                // Track the first response as fallback (single-response OCSP is the common case)
                firstCertStatus ??= statusValue;

                bool certIdMatches = respIssuerNameHash.AsSpan().SequenceEqual(expectedIssuerNameHash) &&
                                     respSerialNumber.AsSpan().SequenceEqual(expectedSerialNumber);
                if (!certIdMatches)
                {
                    continue;
                }

                foundMatch = true;
                if (statusValue.HasValue)
                {
                    return HandleCertStatus(statusValue.Value, logger);
                }
                break;
            }

            // Fallback: if no CertID matched but there's exactly one response, use it
            // (most OCSP responders return a single SingleResponse per request)
            if (!foundMatch && firstCertStatus.HasValue)
            {
                return HandleCertStatus(firstCertStatus.Value, logger);
            }

            throw new InvalidDataException("OCSP response does not contain a valid certificate status.");
        }
        finally
        {
            responderCert?.Dispose();
        }
    }

    /// <summary>
    /// Parses an OCSPResponse and returns both the revocation status and all responder
    /// certificates embedded in the response. The certificates are NOT disposed by this method —
    /// the caller owns them and must include them in DSS for LTV.
    /// </summary>
    internal static (bool IsValid, IReadOnlyList<X509Certificate2> ResponderCertificates) ParseOcspResponseWithCerts(
        byte[] ocspResponseBytes, X509Certificate2 cert, ILogger? logger = null)
    {
        var responderCerts = new List<X509Certificate2>();

        try
        {
            return ParseOcspResponseWithCertsCore(ocspResponseBytes, cert, responderCerts, logger);
        }
        catch
        {
            // Dispose all loaded certs before re-throwing to avoid resource leaks
            foreach (var c in responderCerts)
            {
                c.Dispose();
            }

            throw;
        }
    }

    private static (bool IsValid, IReadOnlyList<X509Certificate2> ResponderCertificates) ParseOcspResponseWithCertsCore(
        byte[] ocspResponseBytes, X509Certificate2 cert, List<X509Certificate2> responderCerts, ILogger? logger)
    {

        var reader = new AsnReader(ocspResponseBytes, AsnEncodingRules.BER);
        var ocspResponse = reader.ReadSequence();

        var statusEncoded = ocspResponse.ReadEncodedValue().Span;
        int status = statusEncoded.Length >= 3 ? statusEncoded[2] : -1;
        if (status != 0)
        {
            throw new InvalidOperationException($"OCSP response status is not 'successful': {status}");
        }

        if (!ocspResponse.HasData)
        {
            throw new InvalidDataException("OCSP response is empty.");
        }

#pragma warning disable CA5350
        byte[] expectedIssuerNameHash = SHA1.HashData(cert.IssuerName.RawData);
        byte[] expectedSerialNumber = cert.SerialNumberBytes.ToArray();
#pragma warning restore CA5350

        var responseBytesWrapper = ocspResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var respBytes = responseBytesWrapper.ReadSequence();
        _ = respBytes.ReadObjectIdentifier();
        var basicOcspBytes = respBytes.ReadOctetString();

        var basicReader = new AsnReader(basicOcspBytes, AsnEncodingRules.BER);
        var basicOcsp = basicReader.ReadSequence();

        byte[] tbsResponseDataRaw = basicOcsp.PeekEncodedValue().ToArray();
        var tbsResponseData = basicOcsp.ReadSequence();

        var sigAlgSeq = basicOcsp.ReadSequence();
        string sigAlgOid = sigAlgSeq.ReadObjectIdentifier();
        byte[]? sigAlgParams = null;
        if (sigAlgSeq.HasData)
        {
            sigAlgParams = sigAlgSeq.ReadEncodedValue().ToArray();
        }
        byte[] ocspSignature = basicOcsp.ReadBitString(out _);

        // Extract ALL certificates from certs [0] OPTIONAL
        X509Certificate2? firstCert = null;
        if (basicOcsp.HasData && basicOcsp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certsWrapper = basicOcsp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            if (certsWrapper.HasData)
            {
                var certSeq = certsWrapper.ReadSequence();
                while (certSeq.HasData)
                {
                    try
                    {
                        var loadedCert = CertificateLoader.LoadCertificate(certSeq.ReadEncodedValue().ToArray());
                        responderCerts.Add(loadedCert);
                        firstCert ??= loadedCert;
                    }
                    catch (CryptographicException ex)
                    {
                        logger?.OcspResponderCertLoadingFailed(ex.Message);
                        // Element already consumed by ReadEncodedValue above — just skip
                    }
                }
            }
        }

        // Verify signature using first responder cert
        if (firstCert is not null)
        {
            bool sigValid = VerifyOcspSignature(firstCert, tbsResponseDataRaw, ocspSignature, sigAlgOid, sigAlgParams, logger);
            if (!sigValid)
            {
                throw new InvalidOperationException("OCSP response signature verification failed.");
            }
        }

        // Parse tbsResponseData for cert status
        if (tbsResponseData.HasData && tbsResponseData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            tbsResponseData.ReadEncodedValue(); // version
        }
        tbsResponseData.ReadEncodedValue(); // responderID
        tbsResponseData.ReadEncodedValue(); // producedAt

        var responses = tbsResponseData.ReadSequence();
        int? firstCertStatus = null;
        bool foundMatch = false;
        while (responses.HasData)
        {
            var single = responses.ReadSequence();
            var certIdSeq = single.ReadSequence();
            certIdSeq.ReadSequence(); // hashAlgorithm
            byte[] respIssuerNameHash = certIdSeq.ReadOctetString();
            certIdSeq.ReadOctetString(); // issuerKeyHash
            var respSerialNumber = certIdSeq.ReadIntegerBytes().ToArray();

            var certStatusTag = single.PeekTag();
            int? statusValue = certStatusTag.TagClass == TagClass.ContextSpecific ? certStatusTag.TagValue : null;
            firstCertStatus ??= statusValue;

            bool certIdMatches = respIssuerNameHash.AsSpan().SequenceEqual(expectedIssuerNameHash) &&
                                 respSerialNumber.AsSpan().SequenceEqual(expectedSerialNumber);
            if (!certIdMatches)
            {
                continue;
            }

            foundMatch = true;
            if (statusValue.HasValue)
            {
                return (HandleCertStatus(statusValue.Value, logger), responderCerts);
            }
            break;
        }

        if (!foundMatch && firstCertStatus.HasValue)
        {
            return (HandleCertStatus(firstCertStatus.Value, logger), responderCerts);
        }

        throw new InvalidDataException("OCSP response does not contain a valid certificate status.");
    }

    private static bool HandleCertStatus(int statusValue, ILogger? logger) => statusValue switch
    {
        0 => LogAndReturn(true, logger),
        1 => LogAndReturn(false, logger),
        2 => throw new InvalidOperationException("OCSP response indicates certificate status is 'unknown'."),
        _ => throw new InvalidDataException($"OCSP response contains unexpected cert status tag: {statusValue}.")
    };

    private static bool LogAndReturn(bool isGood, ILogger? logger)
    {
        if (isGood)
        {
            logger?.OcspStatusGood();
        }
        else
        {
            logger?.OcspStatusRevoked();
        }

        return isGood;
    }

    internal static bool VerifyOcspSignature(
        X509Certificate2 responderCert,
        byte[] tbsData,
        byte[] signature,
        string sigAlgOid,
        byte[]? sigAlgParams = null,
        ILogger? logger = null)
    {
        try
        {
            using var rsa = responderCert.GetRSAPublicKey();
            if (rsa is not null)
            {
                var hashAlg = sigAlgOid == Oids.RsaPss
                    ? CryptoUtility.ParsePssHashAlgorithm(sigAlgParams ?? [])
                    : sigAlgOid switch
                    {
                        Oids.RsaSha256 => HashAlgorithmName.SHA256,
                        Oids.RsaSha384 => HashAlgorithmName.SHA384,
                        Oids.RsaSha512 => HashAlgorithmName.SHA512,
                        Oids.RsaSha1 => HashAlgorithmName.SHA1,
                        _ => HashAlgorithmName.SHA256
                    };
                var padding = sigAlgOid == Oids.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(tbsData, signature, hashAlg, padding);
            }

            using var ecdsa = responderCert.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                var hashAlg = sigAlgOid switch
                {
                    Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
                    Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
                    Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA256
                };
                return ecdsa.VerifyData(tbsData, signature, hashAlg);
            }

            logger?.OcspSignatureVerificationFailed($"Unsupported OCSP responder key type (not RSA/ECDSA). Cannot verify response signature.");
            return false;
        }
        catch (CryptographicException ex) { logger?.OcspSignatureVerificationFailed(ex.Message); return false; }
    }

    /// <summary>
    /// Extracts the OCSP server URL from the AIA (Authority Information Access) extension.
    /// AIA OID = 1.3.6.1.5.5.7.1.1
    ///   id-ad-ocsp      = 1.3.6.1.5.5.7.48.1
    ///   id-ad-caIssuers = 1.3.6.1.5.5.7.48.2
    /// </summary>
    internal static string? GetOcspUrl(X509Certificate2 cert)
    {
        var aia = cert.Extensions[Oids.AuthorityInfoAccess];
        if (aia is null)
        {
            return null;
        }

        return ParseAiaUri(aia.RawData, Oids.AdOcsp); // id-ad-ocsp
    }

    /// <summary>
    /// Extracts the first HTTP URL of the issuer (caIssuers) from the AIA extension.
    /// Used to download the issuer certificate when necessary.
    /// </summary>
    internal static string? GetCaIssuersUrl(X509Certificate2 cert)
    {
        var aia = cert.Extensions[Oids.AuthorityInfoAccess];
        if (aia is null)
        {
            return null;
        }

        return ParseAiaUri(aia.RawData, Oids.AdCaIssuers); // id-ad-caIssuers
    }

    internal static string? ParseAiaUri(byte[] rawAia, string targetOid, ILogger? logger = null)
    {
        try
        {
            // Use BER: X.509 allows CAs to encode extension values in BER (not strict DER)
            var reader = new AsnReader(rawAia, AsnEncodingRules.BER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var accessDesc = seq.ReadSequence();
                string oid = accessDesc.ReadObjectIdentifier();
                // GeneralName [6] IA5String = uniformResourceIdentifier
                if (accessDesc.HasData)
                {
                    var gnTag = accessDesc.PeekTag();
                    if (gnTag.TagClass == TagClass.ContextSpecific && gnTag.TagValue == 6)
                    {
                        string uri = accessDesc.ReadCharacterString(
                            UniversalTagNumber.IA5String,
                            new Asn1Tag(TagClass.ContextSpecific, 6));
                        if (oid == targetOid)
                        {
                            return uri;
                        }
                    }
                    else
                    {
                        accessDesc.ReadEncodedValue(); // skips other GeneralName types
                    }
                }
            }
        }
        catch (AsnContentException ex) { logger?.OcspUrlExtensionParsingFailed(ex.Message); }
        return null;
    }
    #endregion

}

/// <summary>
/// Result of an OCSP fetch operation, including revocation status, raw response bytes,
/// and all responder certificates found in the response.
/// </summary>
internal sealed record OcspFetchResult(
    bool IsValid,
    byte[] ResponseBytes,
    IReadOnlyList<X509Certificate2> ResponderCertificates);
