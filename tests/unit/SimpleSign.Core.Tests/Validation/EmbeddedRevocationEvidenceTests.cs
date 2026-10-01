using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

public sealed class EmbeddedRevocationEvidenceTests
{
    [Fact]
    public void CoversAll_ValidCrlForEveryCertificate_ReturnsTrue()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        byte[] leafCrl = SyntheticPki.BuildGoodCrl(pki.IntermediateCa);
        byte[] intermediateCrl = SyntheticPki.BuildGoodCrl(pki.RootCa);

        bool covered = EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf, pki.IntermediateCa, pki.RootCa], [],
            [leafCrl, intermediateCrl], DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.True(covered);
    }

    [Fact]
    public void CoversAll_MissingLaterCertificateCrl_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        byte[] leafCrl = SyntheticPki.BuildGoodCrl(pki.IntermediateCa);

        bool covered = EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf, pki.IntermediateCa, pki.RootCa], [],
            [leafCrl], DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.False(covered);
    }

    [Fact]
    public void CoversCertificate_MismatchedOrCorruptedCrl_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        var ocsp = new OcspClient(httpClient);
        byte[] wrongIssuerCrl = SyntheticPki.BuildGoodCrl(pki.RootCa);
        byte[] damagedCrl = SyntheticPki.BuildGoodCrl(pki.IntermediateCa);
        damagedCrl[^1] ^= 0x01;

        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [wrongIssuerCrl], DateTimeOffset.UtcNow, ocsp));
        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [damagedCrl], DateTimeOffset.UtcNow, ocsp));
    }

    [Fact]
    public void CoversCertificate_RevokedCertificate_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();

        bool covered = EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [pki.BuildLeafCrl()],
            DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.False(covered);
    }

    [Fact]
    public void CoversCertificate_GoodAndRevokedCrl_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();

        bool covered = EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [],
            [SyntheticPki.BuildGoodCrl(pki.IntermediateCa), pki.BuildLeafCrl()],
            DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.False(covered);
    }
}
