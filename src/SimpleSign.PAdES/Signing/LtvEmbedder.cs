using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Embeds revocation data (CRL + OCSP) and VRI (Validation Related Information)
/// in the PDF DSS (Document Security Store) for LTV (Long Term Validation).
/// The resulting PDF can be validated offline even after certificate expiration.
/// Conforms to PAdES Part 4 (ETSI EN 319 142-1), Annex A.
/// </summary>
public sealed class LtvEmbedder
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for downloading CRL/OCSP.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses the shared instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public LtvEmbedder(HttpClient? httpClient = null, ILogger? logger = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates an embedder using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public LtvEmbedder(IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Collects revocation data (CRL + OCSP) from all certificates in the chain
    /// and embeds them in the PDF as an incremental update (DSS dictionary with VRI).
    /// </summary>
    /// <param name="signedPdf">The signed PDF bytes.</param>
    /// <param name="certificateChain">Full certificate chain (signer + intermediates + root).</param>
    /// <param name="timestampTokenBytes">Optional raw DER bytes of the signature timestamp token (for VRI /TS).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes with embedded LTV data.</returns>
    public async Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        byte[]? timestampTokenBytes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(certificateChain);

        const int MaxIterations = 10;
        var crlData = new List<byte[]>();
        var ocspData = new List<byte[]>();
        var allCerts = new List<X509Certificate2>(certificateChain);
        var ocspClient = new OcspClient(_httpClient, _logger);

        // Pre-merge TSA certificates if timestamp token provided
        if (timestampTokenBytes is { Length: > 0 })
        {
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(timestampTokenBytes);
            foreach (var tsaCert in tsaCerts)
            {
                if (!allCerts.Any(c => c.Thumbprint.Equals(tsaCert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                {
                    allCerts.Add(tsaCert);
                }
                else
                {
                    tsaCert.Dispose();
                }
            }
        }

        // Iterative stabilisation loop: process certificates until no new ones are discovered
        var processedThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var workingSet = new Queue<X509Certificate2>(allCerts);
        int iteration = 0;

        while (workingSet.Count > 0 && iteration < MaxIterations)
        {
            iteration++;
            var nextRound = new List<X509Certificate2>();

            while (workingSet.Count > 0)
            {
                var cert = workingSet.Dequeue();

                if (!processedThumbprints.Add(cert.Thumbprint))
                {
                    continue; // Already processed
                }

                // Check for id-pkix-ocsp-nocheck — skip revocation check for this cert
                if (HasOcspNoCheckExtension(cert))
                {
                    _logger.LtvProcessingCert($"{cert.Subject} (OcspNoCheck — skipping revocation)");
                    continue;
                }

                _logger.LtvProcessingCert(cert.Subject);

                // Try OCSP first (smaller, faster, more current)
                var ocspUrl = OcspClient.GetOcspUrl(cert);
                if (ocspUrl is not null)
                {
                    try
                    {
                        var issuerCert = allCerts.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData));
                        var ocspResult = await ocspClient.FetchOcspResponseAsync(cert, issuerCert, ocspUrl, cancellationToken).ConfigureAwait(false);
                        ocspData.Add(ocspResult.ResponseBytes);

                        // Queue responder certificates for next round
                        foreach (var respCert in ocspResult.ResponderCertificates)
                        {
                            if (!processedThumbprints.Contains(respCert.Thumbprint) &&
                                !allCerts.Any(c => c.Thumbprint.Equals(respCert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                            {
                                allCerts.Add(respCert);
                                nextRound.Add(respCert);
                            }
                            else
                            {
                                respCert.Dispose();
                            }
                        }

                        continue; // OCSP succeeded, skip CRL for this cert
                    }
                    catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or InvalidDataException)
                    {
                        _logger.OcspFailedFallingBackToCrl(cert.Subject, ex.Message);
                    }
                }

                // Fallback to CRL
                var crlUrl = CrlClient.GetCrlUrl(cert, _logger);
                if (crlUrl is not null)
                {
                    try
                    {
                        var crl = await ResilientHttp.GetBytesAsync(_httpClient, crlUrl, logger: _logger, ct: cancellationToken).ConfigureAwait(false);
                        if (crl is not null)
                        {
                            crlData.Add(crl);

                            // Chase CRL issuer certificate if it differs from the cert's issuer (indirect CRL)
                            var crlIssuerDn = CrlClient.ExtractCrlIssuerDn(crl, _logger);
                            if (crlIssuerDn is not null)
                            {
                                // Check if any cert in the working set has this DN as subject
                                bool crlIssuerFound = allCerts.Any(c =>
                                    c.SubjectName.RawData.AsSpan().SequenceEqual(crlIssuerDn));

                                if (!crlIssuerFound)
                                {
                                    // Try to fetch the CRL issuer cert via AIA caIssuers
                                    var crlIssuerCert = await TryFetchCrlIssuerCertAsync(crlIssuerDn, cert, cancellationToken).ConfigureAwait(false);
                                    if (crlIssuerCert is not null &&
                                        !processedThumbprints.Contains(crlIssuerCert.Thumbprint) &&
                                        !allCerts.Any(c => c.Thumbprint.Equals(crlIssuerCert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                                    {
                                        allCerts.Add(crlIssuerCert);
                                        nextRound.Add(crlIssuerCert);
                                        _logger.LtvProcessingCert($"CRL issuer discovered: {crlIssuerCert.Subject}");
                                    }
                                    else
                                    {
                                        crlIssuerCert?.Dispose();
                                    }
                                }
                            }
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        _logger.CrlDownloadFailed(ex.Message);
                    }
                }
            }

            // Enqueue newly discovered certificates for next iteration
            foreach (var cert in nextRound)
            {
                workingSet.Enqueue(cert);
            }
        }

        if (crlData is [] && ocspData is [])
        {
            _logger.LtvNoRevocationDataCollected();
            // v0.3.3: even when no LTV data is embedded, the source PDF must end
            // with an EOL marker so any downstream incremental update is LF-preceded.
            // Avoid a full double-copy: check the last byte and only allocate when
            // the trailing EOL is actually missing.
            if (signedPdf.Length > 0 && signedPdf[^1] != (byte)'\n' && signedPdf[^1] != (byte)'\r')
            {
                byte[] result = new byte[signedPdf.Length + 1];
                signedPdf.CopyTo(result, 0);
                result[^1] = (byte)'\n';
                return result;
            }

            return signedPdf;
        }

        _logger.LtvDataCollected(crlData.Count, ocspData.Count, allCerts.Count);

        // Extract signature /Contents hashes for VRI
        var signatureHashes = ExtractSignatureContentHashes(signedPdf);

        // Parse existing DSS for merge (multi-signature support)
        var existingDss = Validation.DssExtractor.ParseExistingDss(signedPdf);

        return AppendDssDictionary(signedPdf, crlData, ocspData, allCerts, signatureHashes, existingDss, timestampTokenBytes);
    }

    /// <summary>
    /// Computes the SHA-1 hash of each signature's /Contents value for VRI dictionary keys.
    /// Per PAdES Part 4, VRI keys are uppercase hex SHA-1 of the DER-encoded signature value.
    /// Only the actual DER content is hashed (trailing padding zeros in /Contents are excluded).
    /// </summary>
    internal static List<string> ExtractSignatureContentHashes(byte[] pdf)
    {
        var hashes = new List<string>();
        var span = pdf.AsSpan();
        ReadOnlySpan<byte> contentsToken = "/Contents <"u8;
        int searchPos = 0;

        while (searchPos < span.Length)
        {
            int matchPos = span[searchPos..].IndexOf(contentsToken);
            if (matchPos < 0)
            {
                break;
            }

            matchPos += searchPos;
            int hexStart = matchPos + contentsToken.Length;

            // Find closing '>'
            int hexEnd = span[hexStart..].IndexOf((byte)'>');
            if (hexEnd < 0)
            {
                break;
            }

            hexEnd += hexStart;

            // Check this looks like a signature /Contents (long hex string, >1000 chars)
            int hexLen = hexEnd - hexStart;
            if (hexLen > 1000)
            {
                // Decode the hex to bytes and compute SHA-1 over actual DER content only
                try
                {
                    string hexString = System.Text.Encoding.Latin1.GetString(span.Slice(hexStart, hexLen));
                    // Pad with leading zero if odd length (hex encoding requires even length)
                    if (hexString.Length % 2 != 0)
                    {
                        hexString = "0" + hexString;
                    }

                    if (hexString.Length > 0)
                    {
                        byte[] sigBytes = Convert.FromHexString(hexString);
                        int derLength = ComputeDerTotalLength(sigBytes);
#pragma warning disable CA5350 // VRI key is defined as SHA-1 by PAdES spec
                        byte[] hash = SHA1.HashData(sigBytes.AsSpan(0, derLength));
#pragma warning restore CA5350
                        hashes.Add(Convert.ToHexString(hash));
                    }
                }
                catch (FormatException)
                {
                    // Not valid hex — skip
                }
            }

            searchPos = hexEnd + 1;
        }

        return hashes;
    }

    /// <summary>
    /// Computes the total length of a DER-encoded structure (tag + length + content).
    /// This is used to determine how many bytes of /Contents are actual CMS data
    /// vs. trailing zero padding added to fill the reserved space.
    /// </summary>
    internal static int ComputeDerTotalLength(byte[] data)
    {
        if (data.Length < 2)
        {
            return data.Length;
        }

        // Skip tag byte
        int pos = 1;

        // Read length
        byte firstLenByte = data[pos++];
        long contentLength;

        if (firstLenByte < 0x80)
        {
            // Short form: length is the byte itself
            contentLength = firstLenByte;
        }
        else if (firstLenByte == 0x80)
        {
            // Indefinite length — not valid DER, fall back to full length
            return data.Length;
        }
        else
        {
            // Long form: lower 7 bits = number of subsequent length bytes
            int numLenBytes = firstLenByte & 0x7F;
            if (numLenBytes > 4 || pos + numLenBytes > data.Length)
            {
                // More than 4 length bytes means > 4GB content — not realistic for CMS in PDFs
                return data.Length;
            }

            contentLength = 0;
            for (int i = 0; i < numLenBytes; i++)
            {
                contentLength = (contentLength << 8) | data[pos++];
            }
        }

        long totalLength = pos + contentLength;
        return totalLength <= data.Length ? (int)totalLength : data.Length;
    }

    private static byte[] AppendDssDictionary(
        byte[] signedPdf,
        List<byte[]> crls,
        List<byte[]> ocsps,
        IReadOnlyList<X509Certificate2> certs,
        List<string> signatureHashes,
        ExistingDssData existingDss,
        byte[]? timestampTokenBytes = null)
    {
        int nextObj = FindNextObjectNumber(signedPdf);
        int dssObjNum = nextObj;
        int catalogObjNum = FindRootObjectNumber(signedPdf);

        var result = new MemoryStream();
        result.Write(signedPdf);
        IncrementalUpdateUtility.EnsureTrailingEol(result);

        var xrefMap = new SortedDictionary<int, long>();
        int nextObjNum = dssObjNum + 1;

        // Write CRL stream objects
        var crlRefs = WriteStreamObjects(result, crls, ref nextObjNum, xrefMap);

        // Write OCSP response stream objects
        var ocspRefs = WriteStreamObjects(result, ocsps, ref nextObjNum, xrefMap);

        // Write certificate stream objects (deduplicated by thumbprint)
        var certThumbprintMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var certRefs = new List<string>();
        foreach (var cert in certs)
        {
            string thumbprint = cert.Thumbprint;
            if (certThumbprintMap.TryGetValue(thumbprint, out var existingRef))
            {
                // Already written — reuse existing object reference
                if (!certRefs.Contains(existingRef))
                {
                    certRefs.Add(existingRef);
                }
                continue;
            }

            int objNum = nextObjNum++;
            string objRef = $"{objNum} 0 R";
            certRefs.Add(objRef);
            certThumbprintMap[thumbprint] = objRef;

            xrefMap[objNum] = result.Position;
            byte[] compressed = CompressWithZlib(cert.RawData);
            var sb = new System.Text.StringBuilder();
            sb.Append($"{objNum} 0 obj\n");
            sb.Append($"<< /Filter /FlateDecode /Length {compressed.Length} >>\n");
            sb.Append("stream\n");
            byte[] header = System.Text.Encoding.Latin1.GetBytes(sb.ToString());
            byte[] footer = System.Text.Encoding.Latin1.GetBytes("\nendstream\nendobj\n");
            result.Write(header);
            result.Write(compressed);
            result.Write(footer);
        }

        // Write /TS stream object for timestamp token if provided
        string? tsRef = null;
        if (timestampTokenBytes is { Length: > 0 })
        {
            int tsObjNum = nextObjNum++;
            xrefMap[tsObjNum] = result.Position;
            byte[] tsCompressed = CompressWithZlib(timestampTokenBytes);
            var tsSb = new System.Text.StringBuilder();
            tsSb.Append($"{tsObjNum} 0 obj\n");
            tsSb.Append($"<< /Filter /FlateDecode /Length {tsCompressed.Length} >>\n");
            tsSb.Append("stream\n");
            result.Write(System.Text.Encoding.Latin1.GetBytes(tsSb.ToString()));
            result.Write(tsCompressed);
            result.Write(System.Text.Encoding.Latin1.GetBytes("\nendstream\nendobj\n"));
            tsRef = $"{tsObjNum} 0 R";
        }

        // Build VRI dictionaries (one per signature)
        var vriEntries = new List<(string Hash, int ObjNum)>();
        foreach (var sigHash in signatureHashes)
        {
            int vriObjNum = nextObjNum++;
            long vriOffset = result.Position;
            xrefMap[vriObjNum] = vriOffset;

            var vriSb = new System.Text.StringBuilder();
            vriSb.Append($"{vriObjNum} 0 obj\n");
            vriSb.Append("<< /Type /VRI\n");
            if (crlRefs is not [])
            {
                vriSb.Append($"   /CRL [{string.Join(" ", crlRefs)}]\n");
            }

            if (ocspRefs is not [])
            {
                vriSb.Append($"   /OCSP [{string.Join(" ", ocspRefs)}]\n");
            }

            if (certRefs is not [])
            {
                vriSb.Append($"   /Cert [{string.Join(" ", certRefs)}]\n");
            }

            if (tsRef is not null)
            {
                vriSb.Append($"   /TS {tsRef}\n");
            }

            // ISO 32000-2 §12.8.4.4: /TU is the time at which the VRI was created
            vriSb.Append($"   /TU (D:{DateTime.UtcNow:yyyyMMddHHmmss}+00'00')\n");

            vriSb.Append(">>\nendobj\n");
            result.Write(System.Text.Encoding.Latin1.GetBytes(vriSb.ToString()));

            vriEntries.Add((sigHash, vriObjNum));
        }

        // Write DSS dictionary — merge existing refs with new refs
        long dssOffset = result.Position;
        xrefMap[dssObjNum] = dssOffset;

        // Merge existing object refs with newly written refs
        var allCrlRefs = MergeRefs(existingDss.CrlObjRefs, crlRefs);
        var allOcspRefs = MergeRefs(existingDss.OcspObjRefs, ocspRefs);
        var allCertRefs = MergeRefs(existingDss.CertObjRefs, certRefs);

        // Merge VRI entries: preserve prior entries + add new ones
        var allVriEntries = new List<(string Hash, int ObjNum)>();
        foreach (var (hash, objNum) in existingDss.VriEntries)
        {
            // Keep prior VRI entries unless overwritten by a new entry with same hash
            if (!vriEntries.Any(v => v.Hash.Equals(hash, StringComparison.OrdinalIgnoreCase)))
            {
                allVriEntries.Add((hash, objNum));
            }
        }

        allVriEntries.AddRange(vriEntries);

        var dssSb = new System.Text.StringBuilder();
        dssSb.Append($"{dssObjNum} 0 obj\n");
        dssSb.Append("<< /Type /DSS\n");
        if (allCrlRefs is not [])
        {
            dssSb.Append($"   /CRLs [{string.Join(" ", allCrlRefs)}]\n");
        }

        if (allOcspRefs is not [])
        {
            dssSb.Append($"   /OCSPs [{string.Join(" ", allOcspRefs)}]\n");
        }

        if (allCertRefs is not [])
        {
            dssSb.Append($"   /Certs [{string.Join(" ", allCertRefs)}]\n");
        }

        if (allVriEntries is not [])
        {
            dssSb.Append("   /VRI <<\n");
            foreach (var (hash, objNum) in allVriEntries)
            {
                dssSb.Append($"      /{hash} {objNum} 0 R\n");
            }

            dssSb.Append("   >>\n");
        }

        dssSb.Append(">>\nendobj\n");
        result.Write(System.Text.Encoding.Latin1.GetBytes(dssSb.ToString()));

        // Write updated catalog with /DSS reference
        long catOffset = result.Position;
        xrefMap[catalogObjNum] = catOffset;

        byte[] updCatalog = BuildUpdatedCatalogDss(catalogObjNum, signedPdf, dssObjNum);
        result.Write(updCatalog);

        int trailerSize = Math.Max(dssObjNum + 1, xrefMap.Keys.Max() + 1);

        long prevXRef = FindLastStartXRef(signedPdf);
        string? trailerId = PdfStructureParser.FindTrailerId(signedPdf);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(signedPdf);

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(signedPdf);
        long xrefOffset = result.Position;

        if (useXRefStream)
        {
            int xrefObjNum = xrefMap.Keys.Max() + 1;
            trailerSize = Math.Max(trailerSize, xrefObjNum + 1);
            var (xrefBytes, _) = PdfSignatureWriter.BuildXrefStream(
                xrefMap, xrefObjNum, trailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            result.Write(xrefBytes);
        }
        else
        {
            string xrefTrailer = BuildDssXrefAndTrailer(xrefMap, trailerSize, catalogObjNum, prevXRef, trailerId, trailerInfo, xrefOffset);
            result.Write(System.Text.Encoding.Latin1.GetBytes(xrefTrailer));
        }

        return result.ToArray();
    }

    /// <summary>
    /// Writes a list of byte arrays as PDF stream objects to the output stream.
    /// Returns indirect reference strings (e.g. "N 0 R") for each written object.
    /// </summary>
    private static List<string> WriteStreamObjects(
        MemoryStream output,
        List<byte[]> dataList,
        ref int nextObjNum,
        SortedDictionary<int, long> offsets)
    {
        var refs = new List<string>();
        foreach (var data in dataList)
        {
            int objNum = nextObjNum++;
            refs.Add($"{objNum} 0 R");

            offsets[objNum] = output.Position;

            // Compress with zlib (FlateDecode) — CRLs can be 1MB+ uncompressed
            byte[] compressed = CompressWithZlib(data);

            var sb = new System.Text.StringBuilder();
            sb.Append($"{objNum} 0 obj\n");
            sb.Append($"<< /Filter /FlateDecode /Length {compressed.Length} >>\n");
            sb.Append("stream\n");
            byte[] header = System.Text.Encoding.Latin1.GetBytes(sb.ToString());
            byte[] footer = System.Text.Encoding.Latin1.GetBytes("\nendstream\nendobj\n");
            output.Write(header);
            output.Write(compressed);
            output.Write(footer);
        }

        return refs;
    }

    private static byte[] CompressWithZlib(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Merges existing object references (from prior DSS) with newly written references.
    /// Existing refs are formatted as "N 0 R" strings. Deduplication is by object number.
    /// </summary>
    private static List<string> MergeRefs(IReadOnlyList<int> existingObjNums, List<string> newRefs)
    {
        var merged = new List<string>();
        var seen = new HashSet<int>();

        // Add existing references first (preserves prior data)
        foreach (int objNum in existingObjNums)
        {
            if (seen.Add(objNum))
            {
                merged.Add($"{objNum} 0 R");
            }
        }

        // Add new references, skipping duplicates
        foreach (string r in newRefs)
        {
            // Extract obj number from "N 0 R" string
            int spaceIdx = r.IndexOf(' ');
            if (spaceIdx > 0 && int.TryParse(r.AsSpan(0, spaceIdx), out int num) && seen.Add(num))
            {
                merged.Add(r);
            }
        }

        return merged;
    }

    private static string BuildDssXrefAndTrailer(
        SortedDictionary<int, long> xrefMap,
        int trailerSize,
        int catalogObjNum,
        long prevXRef,
        string? trailerId,
        string? trailerInfo,
        long xrefOffset)
    {
        var xref = new System.Text.StringBuilder();
        xref.Append("xref\n");

        var sortedKeys = xrefMap.Keys.ToList();
        int idx = 0;
        while (idx < sortedKeys.Count)
        {
            int groupStart = sortedKeys[idx];
            int j = idx;
            while (j + 1 < sortedKeys.Count && sortedKeys[j + 1] == sortedKeys[j] + 1)
            {
                j++;
            }

            int count = j - idx + 1;
            xref.Append($"{groupStart} {count}\n");
            for (int k = idx; k <= j; k++)
            {
                xref.Append($"{xrefMap[sortedKeys[k]]:D10} 00000 n\r\n");
            }

            idx = j + 1;
        }

        xref.Append("trailer\n");
        xref.Append($"<< /Size {Math.Max(trailerSize, xrefMap.Keys.Max() + 1)}\n");
        xref.Append($"   /Root {catalogObjNum} 0 R\n");
        xref.Append($"   /Prev {prevXRef}\n");
        if (trailerId != null)
        {
            xref.Append($"   {trailerId}\n");
        }
        if (trailerInfo != null)
        {
            xref.Append($"   {trailerInfo}\n");
        }
        xref.Append(">>\n");
        xref.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return xref.ToString();
    }

    private static int FindRootObjectNumber(byte[] pdf)
    {
        ReadOnlySpan<byte> rootKey = "/Root "u8;
        var span = pdf.AsSpan();
        int idx = span.LastIndexOf(rootKey);
        if (idx < 0)
        {
            return 1;
        }

        int pos = idx + rootKey.Length;
        int num = 0;
        while (pos < pdf.Length && pdf[pos] >= '0' && pdf[pos] <= '9')
        {
            num = num * 10 + (pdf[pos++] - '0');
        }

        return num > 0 ? num : 1;
    }

    private static byte[] BuildUpdatedCatalogDss(int catalogObjNum, byte[] pdf, int dssObjNum)
    {
        string marker = $"{catalogObjNum} 0 obj";
        byte[] markerBytes = System.Text.Encoding.Latin1.GetBytes(marker);
        int start = -1;
        for (int i = pdf.Length - markerBytes.Length; i >= 0; i--)
        {
            if (pdf.AsSpan(i, markerBytes.Length).SequenceEqual(markerBytes))
            {
                start = i;
                break;
            }
        }
        if (start < 0)
        {
            return System.Text.Encoding.Latin1.GetBytes(
                $"{catalogObjNum} 0 obj\n<< /Type /Catalog /DSS {dssObjNum} 0 R >>\nendobj\n");
        }

        ReadOnlySpan<byte> endobjMarker = "endobj"u8;
        int endobjIdx = pdf.AsSpan(start).IndexOf(endobjMarker);
        int end = endobjIdx >= 0 ? start + endobjIdx + 6 : pdf.Length;

        string original = System.Text.Encoding.Latin1.GetString(pdf, start, end - start);

        // Remove existing /DSS if present
        int dssIdx = original.IndexOf("/DSS ", StringComparison.Ordinal);
        if (dssIdx >= 0)
        {
            int lineEnd = original.IndexOf('\n', dssIdx);
            if (lineEnd >= 0)
            {
                original = original[..dssIdx] + original[(lineEnd + 1)..];
            }
        }

        // Find the position to insert /DSS — just before the closing >> of the top-level dict.
        // Normalise CRLF → LF so Windows / iText / Adobe source PDFs match the sentinel;
        // fall back to a depth-aware search for the top-level dict close when the
        // sentinel is not found (e.g. unusual line endings or nested dicts).
        string normalised = original.Replace("\r\n", "\n", StringComparison.Ordinal);
        int insertIdx = normalised.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertIdx < 0)
        {
            insertIdx = PdfStructureParser.FindOutermostDictClose(normalised);
        }

        if (insertIdx < 0)
        {
            return System.Text.Encoding.Latin1.GetBytes(normalised);
        }

        // Splice against normalised (not original) so the index is correct even when
        // the source catalog contained CRLF line endings.
        string updated = normalised[..insertIdx] + $"   /DSS {dssObjNum} 0 R\n" + normalised[insertIdx..];

        // ISO 32000 §7.3.10: endobj shall be followed by an EOL marker. The next
        // object (XRef stream, written immediately after by the caller) would
        // otherwise start with no EOL predecessor and fail spacingCompliesPDFA.
        if (!updated.EndsWith('\n'))
        {
            updated += "\n";
        }

        return System.Text.Encoding.Latin1.GetBytes(updated);
    }

    private static int FindNextObjectNumber(byte[] pdf)
    {
        ReadOnlySpan<byte> sizeKey = "/Size "u8;
        var span = pdf.AsSpan();
        int idx = span.LastIndexOf(sizeKey);
        if (idx < 0)
        {
            return 10;
        }

        int pos = idx + sizeKey.Length;
        int size = 0;
        while (pos < pdf.Length && pdf[pos] >= '0' && pdf[pos] <= '9')
        {
            size = size * 10 + (pdf[pos++] - '0');
        }

        // Also check highest object number to avoid collisions
        ReadOnlySpan<byte> objMarker = " 0 obj"u8;
        int highest = 0;
        int searchPos = 0;
        while (searchPos < pdf.Length)
        {
            int objIdx = pdf.AsSpan(searchPos).IndexOf(objMarker);
            if (objIdx < 0)
            {
                break;
            }

            int absPos = searchPos + objIdx;
            int numEnd = absPos;
            int numStart = numEnd - 1;
            while (numStart >= 0 && pdf[numStart] >= '0' && pdf[numStart] <= '9')
            {
                numStart--;
            }

            numStart++;
            if (numStart < numEnd)
            {
                int objNum = 0;
                for (int i = numStart; i < numEnd; i++)
                {
                    objNum = objNum * 10 + (pdf[i] - '0');
                }

                if (objNum > highest)
                {
                    highest = objNum;
                }
            }

            searchPos = absPos + objMarker.Length;
        }

        return Math.Max(size, highest + 1);
    }

    private static long FindLastStartXRef(byte[] pdf)
    {
        ReadOnlySpan<byte> marker = "startxref"u8;
        var span = pdf.AsSpan();
        int idx = span.LastIndexOf(marker);
        if (idx < 0)
        {
            return 0;
        }

        int pos = idx + marker.Length;
        while (pos < pdf.Length && (pdf[pos] == ' ' || pdf[pos] == '\n' || pdf[pos] == '\r'))
        {
            pos++;
        }

        long val = 0;
        while (pos < pdf.Length && pdf[pos] >= '0' && pdf[pos] <= '9')
        {
            val = val * 10 + (pdf[pos++] - '0');
        }

        return val;
    }

    /// <summary>
    /// Checks whether a certificate carries the id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1).
    /// Certificates with this extension are exempt from revocation checking.
    /// </summary>
    private static bool HasOcspNoCheckExtension(X509Certificate2 cert) =>
        cert.Extensions[Oids.OcspNoCheck] is not null;

    /// <summary>
    /// Attempts to fetch the CRL issuer certificate via the cert's AIA caIssuers URL.
    /// Returns the certificate if found and its subject matches the expected CRL issuer DN.
    /// Returns null if the certificate cannot be fetched or doesn't match.
    /// </summary>
    private async Task<X509Certificate2?> TryFetchCrlIssuerCertAsync(
        byte[] expectedIssuerDn,
        X509Certificate2 currentCert,
        CancellationToken ct)
    {
        // Try caIssuers from the current cert's AIA extension
        var caIssuersUrl = OcspClient.GetCaIssuersUrl(currentCert);
        if (caIssuersUrl is null)
        {
            return null;
        }

        try
        {
            var certBytes = await ResilientHttp.GetBytesAsync(_httpClient, caIssuersUrl, logger: _logger, ct: ct).ConfigureAwait(false);
            if (certBytes is null)
            {
                return null;
            }

            var fetchedCert = CertificateLoader.LoadCertificate(certBytes);
            if (fetchedCert.SubjectName.RawData.AsSpan().SequenceEqual(expectedIssuerDn))
            {
                return fetchedCert;
            }

            fetchedCert.Dispose();
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or CryptographicException)
        {
            return null;
        }
    }
}
