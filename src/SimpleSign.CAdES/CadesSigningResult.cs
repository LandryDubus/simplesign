namespace SimpleSign.CAdES;

/// <summary>
/// Result of a CAdES signing operation, returned by <see cref="CadesSignerBuilder.SignWithDetailsAsync"/>.
/// Includes the serialized CMS signature and metadata about applied protection levels.
/// </summary>
public sealed class CadesSigningResult
{
    /// <summary>DER-encoded CMS/PKCS#7 SignedData (detached).</summary>
    public byte[] Cms { get; init; } = [];

    /// <summary>Whether a timestamp token was applied (CAdES-B-T or higher).</summary>
    public bool TimestampApplied { get; init; }

    /// <summary>Whether long-term validation data (cert values + revocation) was embedded (CAdES-B-LT or higher).</summary>
    public bool LtvDataEmbedded { get; init; }

    /// <summary>Whether an archive timestamp was applied (CAdES-B-LTA).</summary>
    public bool ArchiveTimestampApplied { get; init; }

    /// <summary>Non-critical warnings (e.g., TSA certificate chain unavailable).</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
