namespace SimpleSign.Brasil.Tests;

[Trait("Category", "Unit")]
public class BrasilExtensionTests
{
    [Fact]
    public void RegionCode_IsBR()
    {
        var ext = new BrasilExtension();
        Assert.Equal("BR", ext.RegionCode);
    }

    [Fact]
    public void DisplayName_IsNotEmpty()
    {
        var ext = new BrasilExtension();
        Assert.False(string.IsNullOrWhiteSpace(ext.DisplayName));
    }

    [Fact]
    public void TrustAnchorProviders_ContainsIcpBrasilAndGovBr()
    {
        var ext = new BrasilExtension();
        var providers = ext.TrustAnchorProviders;

        Assert.Equal(2, providers.Count);
        Assert.Contains(providers, p => p.DisplayName == "ICP-Brasil");
        Assert.Contains(providers, p => p.DisplayName == "Gov.br");
    }

    [Fact]
    public void TrustAnchorProviders_LoadCertificates()
    {
        var ext = new BrasilExtension();
        foreach (var provider in ext.TrustAnchorProviders)
        {
            var certs = provider.GetTrustAnchors();
            Assert.NotEmpty(certs);
        }
    }

    [Fact]
    public void ChainValidationProviders_ContainsTwoProviders()
    {
        var ext = new BrasilExtension();
        Assert.Equal(2, ext.ChainValidationProviders.Count);
    }
}
