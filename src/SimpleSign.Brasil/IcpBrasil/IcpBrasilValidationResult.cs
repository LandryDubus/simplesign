using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>ICP-Brasil chain validation result.</summary>
public sealed class IcpBrasilValidationResult
{
    /// <summary>Indicates whether the certificate chain is valid and trusted.</summary>
    public bool IsChainValid { get; init; }
    /// <summary>Indicates whether the certificate is issued by ICP-Brasil.</summary>
    public bool IsIcpBrasilCertificate { get; init; }
    /// <summary>Detected ICP-Brasil signature policy (AD-RB, AD-RT, AD-RV, AD-RC, or AD-RA).</summary>
    public IcpBrasilPolicy? DetectedPolicy { get; init; }
    /// <summary>Certificate level (A1–A4 for authentication, S1–S4 for confidentiality).</summary>
    public IcpBrasilCertificateLevel? CertificateLevel { get; init; }
    /// <summary>CPF extracted from the SAN field (OID 2.16.76.1.3.1), if present (11 digits, no formatting).</summary>
    public string? Cpf { get; init; }
    /// <summary>CNPJ extracted from the SAN field (OID 2.16.76.1.3.3), if present (14 digits, no formatting).</summary>
    public string? Cnpj { get; init; }
    /// <summary>Formatted CPF as XXX.XXX.XXX-XX, or null if not available.</summary>
    public string? CpfFormatted => Cpf?.Length == 11
        ? $"{Cpf[..3]}.{Cpf[3..6]}.{Cpf[6..9]}-{Cpf[9..]}"
        : Cpf;
    /// <summary>Formatted CNPJ as XX.XXX.XXX/XXXX-XX, or null if not available.</summary>
    public string? CnpjFormatted => Cnpj?.Length == 14
        ? $"{Cnpj[..2]}.{Cnpj[2..5]}.{Cnpj[5..8]}/{Cnpj[8..12]}-{Cnpj[12..]}"
        : Cnpj;
    /// <summary>
    /// Health professional registration info extracted from the SAN (CRM, CRO, or sequential).
    /// Null when the certificate was not issued to a health professional.
    /// Use this to verify prescriptions eletrônicas per CFM/CFF regulations.
    /// </summary>
    public HealthProfessionalInfo? HealthProfessional { get; init; }
    /// <summary>Certificate chain elements with individual validation results.</summary>
    public IReadOnlyList<IcpBrasilChainElement> ChainElements { get; init; } = [];
    /// <summary>Bundled AC Raiz (root CA) certificates used for chain building.</summary>
    public IReadOnlyList<X509Certificate2> AcRaizCertificates { get; init; } = [];
    /// <summary>Validation errors found during chain validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];
    /// <summary>Non-blocking warnings found during chain validation.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>Indicates whether the overall validation passed (chain valid and no errors).</summary>
    public bool IsValid => IsChainValid && Errors.Count == 0;
}
