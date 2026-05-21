namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// Health professional information extracted from an ICP-Brasil certificate SAN.
/// Present when the certificate was issued to a licensed health professional
/// (e.g., medical doctor, dentist) for use in electronic prescriptions.
/// </summary>
public sealed class HealthProfessionalInfo
{
    /// <summary>Issuing council type (CRM, CRO, or Sequential).</summary>
    public required HealthProfessionalCouncil Council { get; init; }

    /// <summary>
    /// Registration number as encoded in the SAN.
    /// For CRM/CRO: state code (2 chars) followed by the registration digits.
    /// For Sequential: digits assigned by the issuing CA.
    /// </summary>
    public required string RegistrationNumber { get; init; }

    /// <summary>
    /// State code prefix extracted from the registration number (CRM/CRO only).
    /// Example: "SP" for São Paulo, "RJ" for Rio de Janeiro.
    /// Null for Sequential council type.
    /// </summary>
    public string? StateCode => Council is HealthProfessionalCouncil.Crm or HealthProfessionalCouncil.Cro
        && RegistrationNumber.Length >= 2
        ? RegistrationNumber[..2]
        : null;

    /// <summary>
    /// Council registration digits (without the state code prefix).
    /// For CRM/CRO: numeric portion after the 2-character state code.
    /// For Sequential: same as <see cref="RegistrationNumber"/>.
    /// </summary>
    public string RegistrationDigits => StateCode is not null
        ? RegistrationNumber[2..]
        : RegistrationNumber;
}
