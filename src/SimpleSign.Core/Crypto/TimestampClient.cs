using System.Formats.Asn1;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// RFC 3161 client for timestamp authority (TSA).
/// Async-first, compatible with ITI-BR TSA and other PAdES providers.
/// </summary>
public sealed class TimestampClient : ITimestampClient
{
    private const int NonceByteLength = 16;

    private static readonly MediaTypeHeaderValue TsqContentType =
        new("application/timestamp-query");

    private readonly HttpClient _httpClient;
    private readonly string _tsaUrl;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes with the TSA URL and a configured HttpClient (dependency injection).
    /// </summary>
    public TimestampClient(HttpClient httpClient, string tsaUrl, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);

        if (!Http.UrlValidator.IsSafeUrl(tsaUrl))
        {
            throw new ArgumentException($"TSA URL is blocked: must be an absolute HTTP(S) URL that does not point to localhost or private networks.", nameof(tsaUrl));
        }

        _httpClient = httpClient;
        _tsaUrl = tsaUrl;
        _logger = logger ?? NullLogger.Instance;

        // Timeout is configured by DefaultHttpClientProvider; avoid mutating shared HttpClient here.
    }

    /// <summary>
    /// Requests a timestamp token for the provided bytes.
    /// </summary>
    /// <param name="dataToTimestamp">The bytes to be timestamped (usually the CMS signature).</param>
    /// <param name="hashAlgorithm">Hash algorithm for the timestamp (SHA-256 recommended).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>DER-encoded timestamp token (TSTInfo encapsulated in CMS).</returns>
    public async Task<byte[]> GetTimestampAsync(
        ReadOnlyMemory<byte> dataToTimestamp,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default)
    {
        byte[] hash = CryptoUtility.ComputeHash(dataToTimestamp.Span, hashAlgorithm);
        string hashOid = GetHashOid(hashAlgorithm);

        var (timestampRequest, requestNonce) = BuildTimeStampRequest(hash, hashOid);
        _logger.TimestampNonceSending(_tsaUrl);
        byte[] timestampResponse = await SendRequestAsync(timestampRequest, cancellationToken).ConfigureAwait(false);
        _logger.TimestampResponseReceived(timestampResponse.Length);

        byte[] token = ParseTimeStampResponse(timestampResponse, requestNonce, hashOid, hash);
        var warnings = new List<string>();
        if (TimestampValidator.Validate(token, dataToTimestamp.ToArray(), null, warnings) != true)
        {
            throw new TimestampException("TSA token signature or signed data is invalid: "
                + string.Join("; ", warnings));
        }
        return token;
    }

    /// <summary>
    /// Embeds a timestamp token in the CMS as an unsigned attribute
    /// <c>id-aa-signatureTimeStampToken</c> (RFC 3161 / PAdES).
    /// </summary>
    public static byte[] EmbedTimestampInCms(byte[] cms, byte[] timestampToken)
    {
        ArgumentNullException.ThrowIfNull(cms);
        ArgumentNullException.ThrowIfNull(timestampToken);

        // Strategy: locate the end of the SignerInfo and insert the unauthenticated attribute
        // This implementation appends the attribute to the existing SignerInfo
        return AppendUnsignedAttribute(cms, Oids.SignatureTimestampToken, timestampToken);
    }

    /// <summary>
    /// Extracts the raw signature value bytes from a DER-encoded CMS/SignedData structure.
    /// Per RFC 3161 §3.1 and PAdES, the id-aa-signatureTimeStampToken must timestamp
    /// the value of SignerInfo.signature (the raw octets, not the DER OCTET STRING wrapper).
    /// </summary>
    public static byte[] ExtractSignatureValue(byte[] cms)
    {
        ArgumentNullException.ThrowIfNull(cms);
        try
        {
            // BER: some CAs produce BER-encoded CMS (indefinite length, etc.)
            var reader = new AsnReader(cms, AsnEncodingRules.BER);
            var contentInfo = reader.ReadSequence();
            _ = contentInfo.ReadObjectIdentifier();
            var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            var signedData = wrapper.ReadSequence();
            _ = signedData.ReadInteger();       // version
            _ = signedData.ReadSetOf();         // digestAlgorithms
            _ = signedData.ReadEncodedValue();  // encapContentInfo
            // certificates [0] OPTIONAL
            if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                _ = signedData.ReadEncodedValue();
            }
            // crls [1] OPTIONAL
            if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                _ = signedData.ReadEncodedValue();
            }
            var signerInfosSet = signedData.ReadSetOf();
            var si = signerInfosSet.ReadSequence();
            _ = si.ReadInteger();       // version
            _ = si.ReadEncodedValue();  // issuerAndSerialNumber
            _ = si.ReadEncodedValue();  // digestAlgorithm
            // signedAttrs [0] OPTIONAL
            if (si.HasData && si.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                _ = si.ReadEncodedValue();
            }
            _ = si.ReadEncodedValue();  // signatureAlgorithm
            return si.ReadOctetString(); // signature value (raw bytes)
        }
        catch (AsnContentException ex)
        {
            throw new InvalidDataException($"Failed to extract signature value from CMS: {ex.Message}", ex);
        }
    }

    #region TimeStampRequest construction (ASN.1 / RFC 3161)

    private static (byte[] RequestBytes, System.Numerics.BigInteger Nonce) BuildTimeStampRequest(byte[] hash, string hashOid)
    {
        var nonce = new byte[NonceByteLength];
        RandomNumberGenerator.Fill(nonce);
        var nonceValue = new System.Numerics.BigInteger(nonce, isUnsigned: true);

        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence()) // TimeStampReq
        {
            // version = 1
            writer.WriteInteger(1);

            // messageImprint: AlgorithmIdentifier + hash
            using (writer.PushSequence())
            {
                using (writer.PushSequence()) // AlgorithmIdentifier
                {
                    writer.WriteObjectIdentifier(hashOid);
                    if (hashOid is not (Oids.Sha3_256 or Oids.Sha3_384 or Oids.Sha3_512))
                    {
                        writer.WriteNull();
                    }
                }
                writer.WriteOctetString(hash);
            }

            // nonce (random 128-bit) to prevent replay
            writer.WriteInteger(nonceValue);

            // certReq = true (requests the TSA certificate in the response)
            writer.WriteBoolean(true);
        }

        return (writer.Encode(), nonceValue);
    }

    private async Task<byte[]> SendRequestAsync(byte[] timestampRequest, CancellationToken ct)
    {
        using var content = new ByteArrayContent(timestampRequest);
        content.Headers.ContentType = TsqContentType;

        using var response = await ResilientHttp.PostAsync(_httpClient, _tsaUrl, content, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new TimestampException(
                $"TSA request failed: HTTP {(int)response.StatusCode} {response.ReasonPhrase}",
                new Uri(_tsaUrl),
                (int)response.StatusCode);
        }

        var contentType = response.Content.Headers.ContentType?.MediaType;
        if (contentType != "application/timestamp-reply")
        {
            throw new TimestampException(
                $"Unexpected TSA response content type: '{contentType}'",
                new Uri(_tsaUrl));
        }

        return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }
    #endregion

    #region TimeStampResponse parsing (ASN.1 / RFC 3161)

    private static byte[] ParseTimeStampResponse(
        byte[] timestampResponse,
        System.Numerics.BigInteger requestNonce,
        string expectedHashOid,
        ReadOnlySpan<byte> expectedHash)
    {
        try
        {
            // BER: some TSA servers (e.g. Gov.br ITI) may respond with BER encoding.
            var reader = new AsnReader(timestampResponse, AsnEncodingRules.BER);
            var seq = reader.ReadSequence();
            var statusSeq = seq.ReadSequence();
            int status = (int)statusSeq.ReadInteger();

            if (status != 0 && status != 1)
            {
                string statusText = status switch
                {
                    2 => "rejection",
                    3 => "waiting",
                    4 => "revocationWarning",
                    5 => "revocationNotification",
                    _ => $"unknown({status})"
                };
                throw new TimestampException($"TSA rejected the request: {statusText}");
            }

            if (!seq.HasData)
            {
                throw new TimestampException("TSA response does not contain a TimeStampToken.");
            }

            byte[] tokenBytes = seq.ReadEncodedValue().ToArray();
            ValidateTimestampTokenBinding(tokenBytes, requestNonce, expectedHashOid, expectedHash);
            return tokenBytes;
        }
        catch (TimestampException)
        {
            throw;
        }
        catch (AsnContentException ex)
        {
            throw new TimestampException("TSA returned a malformed timestamp response.", ex);
        }
    }

    private static void ValidateTimestampTokenBinding(
        byte[] timestampToken,
        System.Numerics.BigInteger requestNonce,
        string expectedHashOid,
        ReadOnlySpan<byte> expectedHash)
    {
        var tokenReader = new AsnReader(timestampToken, AsnEncodingRules.BER);
        var contentInfo = tokenReader.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        if (contentType != Oids.SignedData)
        {
            throw new TimestampException("TSA token is not CMS SignedData.");
        }

        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadSetOf();
        var encap = signedData.ReadSequence();
        string encapsulatedContentType = encap.ReadObjectIdentifier();
        if (encapsulatedContentType != Oids.TimestampInfoContentType)
        {
            throw new TimestampException("TSA token does not encapsulate TSTInfo content.");
        }

        if (!encap.HasData)
        {
            throw new TimestampException("TSA token does not contain encapsulated TSTInfo bytes.");
        }

        var tstInfoWrapper = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        byte[] tstInfoBytes = tstInfoWrapper.ReadOctetString();
        var tstInfoReader = new AsnReader(tstInfoBytes, AsnEncodingRules.BER);
        var tstInfo = tstInfoReader.ReadSequence();
        _ = tstInfo.ReadInteger();
        _ = tstInfo.ReadObjectIdentifier();

        var messageImprint = tstInfo.ReadSequence();
        var hashAlgorithm = messageImprint.ReadSequence();
        string actualHashOid = hashAlgorithm.ReadObjectIdentifier();
        if (hashAlgorithm.HasData)
        {
            _ = hashAlgorithm.ReadEncodedValue();
        }
        byte[] actualHash = messageImprint.ReadOctetString();

        if (actualHashOid != expectedHashOid)
        {
            throw new TimestampException(
                $"TSA token messageImprint uses '{actualHashOid}', expected '{expectedHashOid}'.");
        }

        if (actualHash.Length != expectedHash.Length
            || !CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
        {
            throw new TimestampException("TSA token messageImprint does not match the requested data.");
        }

        _ = tstInfo.ReadInteger();
        _ = tstInfo.ReadEncodedValue();

        if (tstInfo.HasData
            && tstInfo.PeekTag() is { TagClass: TagClass.Universal, TagValue: (int)UniversalTagNumber.Sequence })
        {
            _ = tstInfo.ReadEncodedValue();
        }

        if (tstInfo.HasData
            && tstInfo.PeekTag() is { TagClass: TagClass.Universal, TagValue: (int)UniversalTagNumber.Boolean })
        {
            _ = tstInfo.ReadBoolean();
        }

        if (!tstInfo.HasData
            || tstInfo.PeekTag() is not { TagClass: TagClass.Universal, TagValue: (int)UniversalTagNumber.Integer })
        {
            throw new TimestampException("TSA token did not echo the request nonce.");
        }

        var responseNonce = tstInfo.ReadInteger();
        if (responseNonce != requestNonce)
        {
            throw new TimestampException("TSA token nonce does not match the request nonce.");
        }
    }
    #endregion

    #region Timestamp embedding in CMS

    private static byte[] AppendUnsignedAttribute(byte[] cms, string attrOid, byte[] attrValue)
    {
        // Locates the end of the SignerInfo to insert the unauthenticated attribute.
        // Approach: simple parse of the CMS DER to find the last SignerInfo
        // and add the unauthenticatedAttrs [1] IMPLICIT.
        //
        // For this version, we use the full-rewrite approach via AsnReader/Writer.
        var reader = new AsnReader(cms, AsnEncodingRules.DER);
        return RewriteCmsWithTimestamp(reader, attrOid, attrValue);
    }

    private static byte[] RewriteCmsWithTimestamp(AsnReader outerReader, string attrOid, byte[] attrValue)
    {
        // Reads ContentInfo
        var contentInfoSeq = outerReader.ReadSequence();
        string contentOid = contentInfoSeq.ReadObjectIdentifier();

        // [0] EXPLICIT → SignedData SEQUENCE
        var explicitWrapper = contentInfoSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedDataSeq = explicitWrapper.ReadSequence();

        // Collect all fields from SignedData
        int version = (int)signedDataSeq.ReadInteger();

        // digestAlgorithms SET
        byte[] digestAlgorithms = signedDataSeq.ReadEncodedValue().ToArray();

        // encapContentInfo
        byte[] encapContentInfo = signedDataSeq.ReadEncodedValue().ToArray();

        // certificates [0] OPTIONAL
        byte[]? certificates = null;
        if (signedDataSeq.HasData && signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            certificates = signedDataSeq.ReadEncodedValue().ToArray();
        }

        // crls [1] OPTIONAL
        byte[]? crls = null;
        if (signedDataSeq.HasData && signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            crls = signedDataSeq.ReadEncodedValue().ToArray();
        }

        // signerInfos SET
        var signerInfosTag = signedDataSeq.ReadSetOf();
        byte[] signerInfoBytes = signerInfosTag.ReadEncodedValue().ToArray();

        // Rewrite with the timestamp embedded in the signerInfo
        byte[] newSignerInfo = AddUnsignedAttrToSignerInfo(signerInfoBytes, attrOid, attrValue);

        // Rebuilds the SignedData
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // ContentInfo
        {
            writer.WriteObjectIdentifier(contentOid);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (writer.PushSequence()) // SignedData
                {
                    writer.WriteInteger(version);
                    writer.WriteEncodedValue(digestAlgorithms);
                    writer.WriteEncodedValue(encapContentInfo);

                    if (certificates is not null)
                    {
                        writer.WriteEncodedValue(certificates);
                    }
                    if (crls is not null)
                    {
                        writer.WriteEncodedValue(crls);
                    }

                    using (writer.PushSetOf()) // signerInfos
                    {
                        writer.WriteEncodedValue(newSignerInfo);
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] AddUnsignedAttrToSignerInfo(byte[] signerInfoBytes, string attrOid, byte[] attrValue)
    {
        var reader = new AsnReader(signerInfoBytes, AsnEncodingRules.DER);
        var siSeq = reader.ReadSequence();

        // Reads all fields of the SignerInfo
        int version = (int)siSeq.ReadInteger();
        byte[] issuerAndSerial = siSeq.ReadEncodedValue().ToArray();
        byte[] digestAlg = siSeq.ReadEncodedValue().ToArray();

        // signedAttrs [0] IMPLICIT OPTIONAL
        byte[]? signedAttrs = null;
        if (siSeq.HasData && siSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            signedAttrs = siSeq.ReadEncodedValue().ToArray();
        }

        byte[] signatureAlg = siSeq.ReadEncodedValue().ToArray();
        byte[] signature = siSeq.ReadEncodedValue().ToArray();

        // unsignedAttrs [1] IMPLICIT OPTIONAL — add or extend
        var unsignedAttrs = new List<byte[]>();
        if (siSeq.HasData && siSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            var existingAttrs = siSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (existingAttrs.HasData)
            {
                unsignedAttrs.Add(existingAttrs.ReadEncodedValue().ToArray());
            }
        }

        // Rebuilds the SignerInfo
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(version);
            writer.WriteEncodedValue(issuerAndSerial);
            writer.WriteEncodedValue(digestAlg);

            if (signedAttrs is not null)
            {
                writer.WriteEncodedValue(signedAttrs);
            }

            writer.WriteEncodedValue(signatureAlg);
            writer.WriteEncodedValue(signature);

            // unsignedAttrs [1] IMPLICIT
            using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                foreach (byte[] attribute in unsignedAttrs)
                {
                    writer.WriteEncodedValue(attribute);
                }
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(attrOid);
                    using (writer.PushSetOf())
                    {
                        writer.WriteEncodedValue(attrValue);
                    }
                }
            }
        }

        return writer.Encode();
    }
    #endregion

    private static string GetHashOid(HashAlgorithmName alg) => alg switch
    {
        _ when alg == HashAlgorithmName.SHA256 => Oids.Sha256,
        _ when alg == HashAlgorithmName.SHA384 => Oids.Sha384,
        _ when alg == HashAlgorithmName.SHA512 => Oids.Sha512,
        _ when alg == HashAlgorithmName.SHA3_256 => Oids.Sha3_256,
        _ when alg == HashAlgorithmName.SHA3_384 => Oids.Sha3_384,
        _ when alg == HashAlgorithmName.SHA3_512 => Oids.Sha3_512,
        _ => throw new NotSupportedException($"Hash algorithm '{alg.Name}' is not supported.")
    };
}
