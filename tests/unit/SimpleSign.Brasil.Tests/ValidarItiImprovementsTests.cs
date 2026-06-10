using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.ValidarIti;

namespace SimpleSign.Brasil.Tests;

/// <summary>
/// Tests for improvements based on the ITI VALIDAR developer guide:
/// - CPF/CNPJ in <see cref="IcpBrasilValidationResult"/>
/// - Health professional OIDs (CRM/CRO) for electronic prescriptions
/// - <see cref="ValidarItiUrlBuilder"/>
/// - Extended Policy OIDs (DOC-ICP-15.03 all versions)
/// </summary>
[Trait("Category", "Unit")]
public sealed class ValidarItiImprovementsTests
{
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string CertPoliciesOid = "2.5.29.32";

    // ── ValidarItiUrlBuilder ─────────────────────────────────────────────────

    [Fact(DisplayName = "ValidarItiUrlBuilder.BaseUrl is VALIDAR portal URL")]
    public void BaseUrl_IsValidarPortal() =>
        ValidarItiUrlBuilder.BaseUrl.ShouldBe("https://validar.iti.gov.br/");

    [Fact(DisplayName = "ValidarItiUrlBuilder.ForDocument encodes document URL correctly")]
    public void ForDocument_String_EncodesUrl()
    {
        string docUrl = "https://example.com/doc.pdf";
        ValidarItiUrlBuilder.ForDocument(docUrl)
            .ShouldBe($"https://validar.iti.gov.br/?document={Uri.EscapeDataString(docUrl)}");
    }

    [Fact(DisplayName = "ValidarItiUrlBuilder.ForDocument with URI encodes correctly")]
    public void ForDocument_Uri_EncodesUrl()
    {
        var uri = new Uri("https://example.com/assinado.pdf");
        ValidarItiUrlBuilder.ForDocument(uri)
            .ShouldBe($"https://validar.iti.gov.br/?document={Uri.EscapeDataString(uri.ToString())}");
    }

    [Fact(DisplayName = "ValidarItiUrlBuilder.ForDocument throws on empty URL")]
    public void ForDocument_EmptyUrl_Throws() =>
        Should.Throw<ArgumentException>(() => ValidarItiUrlBuilder.ForDocument(""));

    [Fact(DisplayName = "ValidarItiUrlBuilder.ForDocument throws on null URI")]
    public void ForDocument_NullUri_Throws() =>
        Should.Throw<ArgumentNullException>(() => ValidarItiUrlBuilder.ForDocument((Uri)null!));

    // ── Health professional OID extraction ───────────────────────────────────

    [Fact(DisplayName = "ExtractHealthProfessional returns CRM when OID 2.16.76.1.3.4 present")]
    public void ExtractHealthProfessional_CrmOid_ReturnsCrm()
    {
        using var cert = CreateCertWithSan([("2.16.76.1.3.4", "SP123456")]);
        var info = IcpBrasilChainValidator.ExtractHealthProfessional(cert);
        info.ShouldNotBeNull();
        info.Council.ShouldBe(HealthProfessionalCouncil.Crm);
        info.RegistrationNumber.ShouldBe("SP123456");
        info.StateCode.ShouldBe("SP");
        info.RegistrationDigits.ShouldBe("123456");
    }

    [Fact(DisplayName = "ExtractHealthProfessional returns CRO when OID 2.16.76.1.3.5 present")]
    public void ExtractHealthProfessional_CroOid_ReturnsCro()
    {
        using var cert = CreateCertWithSan([("2.16.76.1.3.5", "RJ98765")]);
        var info = IcpBrasilChainValidator.ExtractHealthProfessional(cert);
        info.ShouldNotBeNull();
        info.Council.ShouldBe(HealthProfessionalCouncil.Cro);
        info.RegistrationNumber.ShouldBe("RJ98765");
        info.StateCode.ShouldBe("RJ");
    }

    [Fact(DisplayName = "ExtractHealthProfessional returns Sequential when OID 2.16.76.1.3.6 present")]
    public void ExtractHealthProfessional_SequentialOid_ReturnsSequential()
    {
        using var cert = CreateCertWithSan([("2.16.76.1.3.6", "0000001234")]);
        var info = IcpBrasilChainValidator.ExtractHealthProfessional(cert);
        info.ShouldNotBeNull();
        info.Council.ShouldBe(HealthProfessionalCouncil.Sequential);
        info.RegistrationNumber.ShouldBe("0000001234");
        info.StateCode.ShouldBeNull();
        info.RegistrationDigits.ShouldBe("0000001234");
    }

    [Fact(DisplayName = "ExtractHealthProfessional returns null when no health OID present")]
    public void ExtractHealthProfessional_NoHealthOid_ReturnsNull()
    {
        // Only CPF OID — not a health certificate
        using var cert = CreateCertWithSan([("2.16.76.1.3.1", "       12345678901   ")]);
        var info = IcpBrasilChainValidator.ExtractHealthProfessional(cert);
        info.ShouldBeNull();
    }

    [Fact(DisplayName = "ExtractHealthProfessional returns null for cert without SAN")]
    public void ExtractHealthProfessional_NoSan_ReturnsNull()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=NoSan", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        IcpBrasilChainValidator.ExtractHealthProfessional(cert).ShouldBeNull();
    }

    // ── IcpBrasilValidationResult CPF/CNPJ properties ───────────────────────

    [Fact(DisplayName = "IcpBrasilValidationResult.CpfFormatted formats 11-digit CPF correctly")]
    public void IcpBrasilValidationResult_CpfFormatted_FormatsCorrectly()
    {
        var result = new IcpBrasilValidationResult { Cpf = "12345678901" };
        result.CpfFormatted.ShouldBe("123.456.789-01");
    }

    [Fact(DisplayName = "IcpBrasilValidationResult.CnpjFormatted formats 14-digit CNPJ correctly")]
    public void IcpBrasilValidationResult_CnpjFormatted_FormatsCorrectly()
    {
        var result = new IcpBrasilValidationResult { Cnpj = "12345678000195" };
        result.CnpjFormatted.ShouldBe("12.345.678/0001-95");
    }

    [Fact(DisplayName = "IcpBrasilValidationResult.CpfFormatted is null when Cpf is null")]
    public void IcpBrasilValidationResult_CpfFormatted_NullWhenCpfNull()
    {
        var result = new IcpBrasilValidationResult();
        result.CpfFormatted.ShouldBeNull();
    }

    [Fact(DisplayName = "IcpBrasilValidationResult.CnpjFormatted is null when Cnpj is null")]
    public void IcpBrasilValidationResult_CnpjFormatted_NullWhenCnpjNull()
    {
        var result = new IcpBrasilValidationResult();
        result.CnpjFormatted.ShouldBeNull();
    }

    // ── Policy OIDs extended coverage ────────────────────────────────────────

    [Theory(DisplayName = "DetectPolicy detects AD-RB via v1/v2/v3 PF and PJ OIDs")]
    [InlineData("2.16.76.1.7.1.1.1.1")] // PF v1
    [InlineData("2.16.76.1.7.1.1.1.2")] // PF v2
    [InlineData("2.16.76.1.7.1.1.1.3")] // PF v3
    [InlineData("2.16.76.1.7.1.1.2.1")] // PJ v1
    [InlineData("2.16.76.1.7.1.1.2.2")] // PJ v2
    [InlineData("2.16.76.1.7.1.1.2.3")] // PJ v3
    public void DetectPolicy_AdRb_AllVersions(string policyOid)
    {
        using var cert = CreateCertWithPolicy(policyOid);
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBe(IcpBrasilPolicy.AdRb);
    }

    [Theory(DisplayName = "DetectPolicy detects AD-RT via v1/v2/v3 PF and PJ OIDs")]
    [InlineData("2.16.76.1.7.1.2.1.1")]
    [InlineData("2.16.76.1.7.1.2.1.2")]
    [InlineData("2.16.76.1.7.1.2.1.3")]
    [InlineData("2.16.76.1.7.1.2.2.1")]
    [InlineData("2.16.76.1.7.1.2.2.2")]
    [InlineData("2.16.76.1.7.1.2.2.3")]
    public void DetectPolicy_AdRt_AllVersions(string policyOid)
    {
        using var cert = CreateCertWithPolicy(policyOid);
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBe(IcpBrasilPolicy.AdRt);
    }

    [Theory(DisplayName = "DetectPolicy detects AD-RA via v1/v2/v3 OIDs")]
    [InlineData("2.16.76.1.7.1.5.1.1")]
    [InlineData("2.16.76.1.7.1.5.1.2")]
    [InlineData("2.16.76.1.7.1.5.2.1")]
    [InlineData("2.16.76.1.7.1.5.2.3")]
    public void DetectPolicy_AdRa_AllVersions(string policyOid)
    {
        using var cert = CreateCertWithPolicy(policyOid);
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBe(IcpBrasilPolicy.AdRa);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static X509Certificate2 CreateCertWithPolicy(string policyOid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(policyOid);
            }
        }
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=PolicyTest, O=ICP-Brasil", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(CertPoliciesOid, w.Encode(), critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateCertWithSan((string oid, string utf8Value)[] otherNames)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var (oid, utf8Value) in otherNames)
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteObjectIdentifier(oid);
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
                        w.WriteCharacterString(UniversalTagNumber.UTF8String, utf8Value);
                    }
                }
            }
        }
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=SanTest", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(SubjectAltNameOid, w.Encode(), critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
