namespace SimpleSign.Brasil.Constants;

/// <summary>
/// Brazilian OID constants (arc 2.16.76.*).
/// </summary>
internal static class BrasilOids
{
    /// <summary>ICP-Brasil SAN: holder data containing CPF at positions 8–18.</summary>
    internal const string IcpBrasilSanHolderData = "2.16.76.1.3.1";

    /// <summary>ICP-Brasil SAN: CNPJ (14 digits).</summary>
    internal const string IcpBrasilSanCnpj = "2.16.76.1.3.3";

    // ── Health professional OIDs (DOC-ICP-04 / ICP-Brasil SAN extensions) ───────

    /// <summary>
    /// ICP-Brasil SAN: CRM (Conselho Regional de Medicina) registration number.
    /// OID 2.16.76.1.3.4 — used in certificates issued to medical professionals.
    /// Value: state code (2 chars) + CRM digits. Required for electronic prescriptions (CFM).
    /// </summary>
    internal const string IcpBrasilSanCrm = "2.16.76.1.3.4";

    /// <summary>
    /// ICP-Brasil SAN: CRO (Conselho Regional de Odontologia) registration number.
    /// OID 2.16.76.1.3.5 — used in certificates issued to dentists.
    /// Value: state code (2 chars) + CRO digits.
    /// </summary>
    internal const string IcpBrasilSanCro = "2.16.76.1.3.5";

    /// <summary>
    /// ICP-Brasil SAN: sequential number / responsible council registration (CRF, CRM-RES, etc.).
    /// OID 2.16.76.1.3.6 — used in server certificates and health professional certificates.
    /// Value: sequential digits assigned by the issuing CA.
    /// </summary>
    internal const string IcpBrasilSanSequential = "2.16.76.1.3.6";

    /// <summary>
    /// Signature manifest — JSON-encoded AEA evidence (name, CPF, email, IP, auth method).
    /// OID arc: 2.16.76 (Brazil) / 1.12 (electronic signature extensions) / 1.1 (manifest v1).
    /// </summary>
    internal const string SignatureManifest = "2.16.76.1.12.1.1";
}
