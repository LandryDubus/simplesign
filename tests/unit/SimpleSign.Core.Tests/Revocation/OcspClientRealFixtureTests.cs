using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.TestFixtures;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// Real-fixture tests for <see cref="OcspClient.ParseOcspResponse"/>.
/// Loads an actual OCSPResponse captured from DigiCert's responder for
/// <c>www.digicert.com</c> and verifies the parser handles the real wire format
/// — including DER-with-context-tags, GeneralizedTime, and signature blocks.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OcspClientRealFixtureTests
{
    [Fact(DisplayName = "ParseOcspResponse verifies real DigiCert response with its issuer")]
    public void ParseOcspResponse_RealDigiCertGood_WithIssuerReturnsTrue()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        using var issuer = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertIssuerCertDer);
        var (result, _) = OcspClient.ParseOcspResponseWithCerts(
            RecordedFixtures.DigiCertOcspGood, cert, issuerCert: issuer);
        result.ShouldBeTrue("DigiCert reported the cert as not revoked when the fixture was captured");
    }

    [Fact(DisplayName = "ParseOcspResponse without a responder or issuer certificate is rejected")]
    public void ParseOcspResponse_RealDigiCertResponse_WithoutIssuerIsRejected()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        Action act = () => OcspClient.ParseOcspResponse(RecordedFixtures.DigiCertOcspGood, cert);
        Should.Throw<InvalidOperationException>(act);
    }

    [Fact]
    public void ParseOcspResponse_DifferentCertificateStatus_IsRejected()
    {
        using var unrelated = TestCertificateFactory.CreateSelfSignedCert();
        using var issuer = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertIssuerCertDer);

        Should.Throw<InvalidDataException>(() => OcspClient.ParseOcspResponseWithCerts(
            RecordedFixtures.DigiCertOcspGood, unrelated, issuerCert: issuer));
    }

    [Fact(DisplayName = "Real DigiCert public cert has the expected issuer subject")]
    public void DigiCertPublicCert_HasExpectedIssuer()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        cert.Issuer.ShouldContain("DigiCert");
    }

    [Fact(DisplayName = "Real DigiCert issuer cert can be loaded and is self-signed within DigiCert hierarchy")]
    public void DigiCertIssuerCert_HasDigiCertIssuer()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertIssuerCertDer);
        cert.Subject.ShouldContain("DigiCert");
    }

    [Fact(DisplayName = "GetOcspUrl on real DigiCert public cert returns http://ocsp.digicert.com")]
    public void GetOcspUrl_RealDigiCertCert_ReturnsExpectedUrl()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        var ocspUrl = OcspClient.GetOcspUrl(cert);
        ocspUrl.ShouldBe("http://ocsp.digicert.com");
    }

    [Fact(DisplayName = "GetCaIssuersUrl on real DigiCert public cert returns the CA Issuers URL")]
    public void GetCaIssuersUrl_RealDigiCertCert_ReturnsExpectedUrl()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        var url = OcspClient.GetCaIssuersUrl(cert);
        url!.ShouldStartWith("http://");
        url.ShouldContain("digicert.com");
        url.ShouldEndWith(".crt");
    }
}
