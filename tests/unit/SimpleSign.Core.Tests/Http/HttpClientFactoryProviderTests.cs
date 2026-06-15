using Moq;
using Shouldly;
using SimpleSign.Core.Http;
using Xunit;

namespace SimpleSign.Core.Tests.Http;

[Trait("Category", "Unit")]
public sealed class HttpClientFactoryProviderTests
{
    [Fact(DisplayName = "GetClient calls factory with the configured client name")]
    public void GetClient_CallsFactoryWithConfiguredClientName()
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("MyClient")).Returns(new HttpClient());
        var provider = new HttpClientFactoryProvider(factory.Object, "MyClient");

        provider.GetClient();

        factory.Verify(f => f.CreateClient("MyClient"), Times.Once);
    }

    [Fact(DisplayName = "GetClient uses default client name 'SimpleSign' when none specified")]
    public void GetClient_UsesDefaultClientName_WhenNoneSpecified()
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("SimpleSign")).Returns(new HttpClient());
        var provider = new HttpClientFactoryProvider(factory.Object);

        provider.GetClient();

        factory.Verify(f => f.CreateClient("SimpleSign"), Times.Once);
    }

    [Fact(DisplayName = "GetClient calls factory on each invocation")]
    public void GetClient_CallsFactoryEachTime()
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(() => new HttpClient());
        var provider = new HttpClientFactoryProvider(factory.Object);

        provider.GetClient();
        provider.GetClient();
        provider.GetClient();

        factory.Verify(f => f.CreateClient("SimpleSign"), Times.Exactly(3));
    }

    [Fact(DisplayName = "Constructor throws ArgumentNullException when factory is null")]
    public void Constructor_NullFactory_ThrowsArgumentNullException() =>
        Should.Throw<ArgumentNullException>(() => new HttpClientFactoryProvider(null!));

    [Fact(DisplayName = "Constructor throws ArgumentException when client name is empty")]
    public void Constructor_EmptyClientName_ThrowsArgumentException()
    {
        var factory = new Mock<IHttpClientFactory>();

        Should.Throw<ArgumentException>(() => new HttpClientFactoryProvider(factory.Object, ""));
    }

    [Fact(DisplayName = "Constructor throws ArgumentException when client name is whitespace")]
    public void Constructor_WhitespaceClientName_ThrowsArgumentException()
    {
        var factory = new Mock<IHttpClientFactory>();

        Should.Throw<ArgumentException>(() => new HttpClientFactoryProvider(factory.Object, "   "));
    }

    [Fact(DisplayName = "HttpClientFactoryProvider implements IHttpClientProvider")]
    public void HttpClientFactoryProvider_ImplementsIHttpClientProvider()
    {
        var factory = new Mock<IHttpClientFactory>();
        var provider = new HttpClientFactoryProvider(factory.Object);

        provider.ShouldBeAssignableTo<IHttpClientProvider>();
    }

    [Fact(DisplayName = "GetClient returns the client produced by the factory")]
    public void GetClient_ReturnsClientFromFactory()
    {
        var expected = new HttpClient();
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("SimpleSign")).Returns(expected);
        var provider = new HttpClientFactoryProvider(factory.Object);

        var result = provider.GetClient();

        result.ShouldBeSameAs(expected);
    }
}
