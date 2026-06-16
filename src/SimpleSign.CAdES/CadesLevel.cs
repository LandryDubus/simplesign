namespace SimpleSign.CAdES;

/// <summary>CAdES conformance level per ETSI EN 319 122-1.</summary>
public enum CadesLevel
{
    /// <summary>Basic signature (signed attributes, signer certificate).</summary>
    Basic = 0,

    /// <summary>With a timestamp token embedded as an unsigned attribute.</summary>
    Timestamped = 1,

    /// <summary>With certificate and revocation references/values (LTV).</summary>
    LongTerm = 2,

    /// <summary>With archival timestamp for long-term preservation.</summary>
    Archive = 3
}
