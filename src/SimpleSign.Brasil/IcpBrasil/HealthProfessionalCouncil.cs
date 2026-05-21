namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// Health professional council type identified from an ICP-Brasil certificate SAN.
/// Used for electronic prescriptions (prescrições eletrônicas) per CFM/CFF regulations.
/// </summary>
public enum HealthProfessionalCouncil
{
    /// <summary>CRM — Conselho Regional de Medicina (medical doctor).</summary>
    Crm,
    /// <summary>CRO — Conselho Regional de Odontologia (dentist).</summary>
    Cro,
    /// <summary>Sequential number assigned by the issuing CA (other health professionals).</summary>
    Sequential,
}
