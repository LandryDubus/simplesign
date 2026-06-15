using System.Reflection;
using Moq;
using Shouldly;
using SimpleSign.Core.Http;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Unit tests for HttpClient management in SignerBuilder.
/// Covers per-operation client resolution, lazy provider evaluation,
/// and the new WithHttpClient / WithHttpClientProvider semantics.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SignerBuilderHttpClientTests
{
    private static SignerBuilder EmptyBuilder() => new(Stream.Null);

    private static T? GetPrivateField<T>(object obj, string fieldName)
    {
        var field = obj.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
        field.ShouldNotBeNull($"Field '{fieldName}' not found on {obj.GetType().Name}");
        return (T?)field!.GetValue(obj);
    }

    // --- WithHttpClient ---

    [Fact(DisplayName = "WithHttpClient returns a new builder instance")]
    public void WithHttpClient_ReturnsNewBuilder()
    {
        var builder = EmptyBuilder();
        var client = new HttpClient();
        var newBuilder = builder.WithHttpClient(client);

        newBuilder.ShouldNotBeSameAs(builder);
    }

    [Fact(DisplayName = "WithHttpClient stores client in _httpClient field")]
    public void WithHttpClient_StoresClientInHttpClientField()
    {
        var builder = EmptyBuilder();
        var client = new HttpClient();

        var newBuilder = builder.WithHttpClient(client);

        GetPrivateField<HttpClient>(newBuilder, "_httpClient").ShouldBeSameAs(client);
    }

    [Fact(DisplayName = "WithHttpClient does not set _tsaHttpClient")]
    public void WithHttpClient_DoesNotSetTsaHttpClient()
    {
        var builder = EmptyBuilder();
        var client = new HttpClient();

        var newBuilder = builder.WithHttpClient(client);

        GetPrivateField<HttpClient>(newBuilder, "_tsaHttpClient").ShouldBeNull();
    }

    [Fact(DisplayName = "WithHttpClient throws ArgumentNullException when client is null")]
    public void WithHttpClient_NullClient_ThrowsArgumentNullException()
    {
        var builder = EmptyBuilder();

        Should.Throw<ArgumentNullException>(() => builder.WithHttpClient(null!));
    }

    [Fact(DisplayName = "WithHttpClient propagates through subsequent fluent calls")]
    public void WithHttpClient_PropagatesThroughFluentChain()
    {
        var builder = EmptyBuilder();
        var client = new HttpClient();

        var finalBuilder = builder
            .WithHttpClient(client)
            .WithTimestamp("http://tsa.example.com");

        GetPrivateField<HttpClient>(finalBuilder, "_httpClient").ShouldBeSameAs(client);
    }

    // --- WithTimestamp with HttpClient ---

    [Fact(DisplayName = "WithTimestamp(url, client) stores client in _tsaHttpClient, not _httpClient")]
    public void WithTimestamp_WithHttpClient_SetsTsaHttpClientOnly()
    {
        var builder = EmptyBuilder();
        var tsaClient = new HttpClient();

        var newBuilder = builder.WithTimestamp("http://tsa.example.com", tsaClient);

        GetPrivateField<HttpClient>(newBuilder, "_tsaHttpClient").ShouldBeSameAs(tsaClient);
        GetPrivateField<HttpClient>(newBuilder, "_httpClient").ShouldBeNull();
    }

    [Fact(DisplayName = "WithTimestamp(url, client) propagates _tsaHttpClient through subsequent fluent calls")]
    public void WithTimestamp_WithHttpClient_PropagatesTsaClientThroughChain()
    {
        var builder = EmptyBuilder();
        var tsaClient = new HttpClient();

        var finalBuilder = builder
            .WithTimestamp("http://tsa.example.com", tsaClient)
            .WithLtv();

        GetPrivateField<HttpClient>(finalBuilder, "_tsaHttpClient").ShouldBeSameAs(tsaClient);
    }

    [Fact(DisplayName = "WithTimestamp(url, client) and WithHttpClient set independent slots")]
    public void WithTimestamp_AndWithHttpClient_SetIndependentSlots()
    {
        var builder = EmptyBuilder();
        var tsaClient = new HttpClient();
        var revocationClient = new HttpClient();

        var finalBuilder = builder
            .WithTimestamp("http://tsa.example.com", tsaClient)
            .WithHttpClient(revocationClient)
            .WithLtv();

        GetPrivateField<HttpClient>(finalBuilder, "_tsaHttpClient").ShouldBeSameAs(tsaClient);
        GetPrivateField<HttpClient>(finalBuilder, "_httpClient").ShouldBeSameAs(revocationClient);
    }

    // --- WithHttpClientProvider ---

    [Fact(DisplayName = "WithHttpClientProvider does not call GetClient at builder-configuration time")]
    public void WithHttpClientProvider_DoesNotCallGetClientAtBuildTime()
    {
        var builder = EmptyBuilder();
        var provider = new Mock<IHttpClientProvider>();
        provider.Setup(p => p.GetClient()).Returns(new HttpClient());

        builder.WithHttpClientProvider(provider.Object);

        provider.Verify(p => p.GetClient(), Times.Never,
            "GetClient must be called lazily at sign time, not during builder configuration");
    }

    [Fact(DisplayName = "WithHttpClientProvider stores provider in _httpClientProvider field")]
    public void WithHttpClientProvider_StoresProvider()
    {
        var builder = EmptyBuilder();
        var provider = new Mock<IHttpClientProvider>().Object;

        var newBuilder = builder.WithHttpClientProvider(provider);

        GetPrivateField<IHttpClientProvider>(newBuilder, "_httpClientProvider").ShouldBeSameAs(provider);
    }

    [Fact(DisplayName = "WithHttpClientProvider propagates through subsequent fluent calls")]
    public void WithHttpClientProvider_PropagatesThroughFluentChain()
    {
        var builder = EmptyBuilder();
        var provider = new Mock<IHttpClientProvider>().Object;

        var finalBuilder = builder
            .WithHttpClientProvider(provider)
            .WithTimestamp("http://tsa.example.com");

        GetPrivateField<IHttpClientProvider>(finalBuilder, "_httpClientProvider").ShouldBeSameAs(provider);
    }

    [Fact(DisplayName = "WithHttpClientProvider throws ArgumentNullException when provider is null")]
    public void WithHttpClientProvider_NullProvider_ThrowsArgumentNullException()
    {
        var builder = EmptyBuilder();

        Should.Throw<ArgumentNullException>(() => builder.WithHttpClientProvider(null!));
    }

    // --- Default provider propagation ---

    [Fact(DisplayName = "Default _httpClientProvider is DefaultHttpClientProvider.Instance")]
    public void DefaultProvider_IsDefaultHttpClientProviderInstance()
    {
        var builder = EmptyBuilder();

        GetPrivateField<IHttpClientProvider>(builder, "_httpClientProvider")
            .ShouldBeSameAs(DefaultHttpClientProvider.Instance);
    }

    [Fact(DisplayName = "_httpClientProvider propagates through WithLtv")]
    public void Provider_PropagatesThroughWithLtv()
    {
        var provider = new Mock<IHttpClientProvider>().Object;
        var builder = EmptyBuilder()
            .WithTimestamp("http://tsa.example.com")
            .WithHttpClientProvider(provider)
            .WithLtv();

        GetPrivateField<IHttpClientProvider>(builder, "_httpClientProvider").ShouldBeSameAs(provider);
    }

    [Fact(DisplayName = "_httpClientProvider propagates through WithArchivalTimestamp")]
    public void Provider_PropagatesThroughWithArchivalTimestamp()
    {
        var provider = new Mock<IHttpClientProvider>().Object;
        var builder = EmptyBuilder()
            .WithTimestamp("http://tsa.example.com")
            .WithHttpClientProvider(provider)
            .WithLtv()
            .WithArchivalTimestamp();

        GetPrivateField<IHttpClientProvider>(builder, "_httpClientProvider").ShouldBeSameAs(provider);
    }

    [Fact(DisplayName = "_tsaHttpClient propagates through WithArchivalTimestamp")]
    public void TsaHttpClient_PropagatesThroughWithArchivalTimestamp()
    {
        var tsaClient = new HttpClient();
        var builder = EmptyBuilder()
            .WithTimestamp("http://tsa.example.com", tsaClient)
            .WithLtv()
            .WithArchivalTimestamp("http://archival-tsa.example.com");

        // The TSA client must reach the final builder so SignCoreAsync uses it for the DocTimeStamp step
        GetPrivateField<HttpClient>(builder, "_tsaHttpClient").ShouldBeSameAs(tsaClient);
        // The revocation slot remains independent
        GetPrivateField<HttpClient>(builder, "_httpClient").ShouldBeNull();
    }

    [Fact(DisplayName = "WithTimestamp(url, client) does not bleed client into revocation slot")]
    public void WithTimestamp_WithHttpClient_DoesNotSetRevocationSlot()
    {
        var tsaClient = new HttpClient();
        var builder = EmptyBuilder()
            .WithTimestamp("http://tsa.example.com", tsaClient)
            .WithLtv();

        // _httpClient (revocation slot) must remain null — TSA client must NOT bleed into it
        GetPrivateField<HttpClient>(builder, "_httpClient").ShouldBeNull();
        GetPrivateField<HttpClient>(builder, "_tsaHttpClient").ShouldBeSameAs(tsaClient);
    }
}
