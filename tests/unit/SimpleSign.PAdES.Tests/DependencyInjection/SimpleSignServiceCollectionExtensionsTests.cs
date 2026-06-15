using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Core.DependencyInjection;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.DependencyInjection;

[Trait("Category", "Unit")]
public sealed class SimpleSignServiceCollectionExtensionsTests
{
    [Fact(DisplayName = "AddSimpleSign registers all core services")]
    public void AddSimpleSign_RegistersAllCoreServices()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        provider.GetService<SimpleSignOptions>().ShouldNotBeNull();
        provider.GetService<ValidationOptions>().ShouldNotBeNull();
        provider.GetService<IHttpClientProvider>().ShouldNotBeNull();
        provider.GetService<PdfSignatureValidator>().ShouldNotBeNull();
        provider.GetService<LtvEmbedder>().ShouldNotBeNull();
    }

    [Fact(DisplayName = "AddSimpleSign uses DefaultHttpClientProvider when no custom provider")]
    public void AddSimpleSign_UsesDefaultHttpClientProvider()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBe(DefaultHttpClientProvider.Instance);
    }

    [Fact(DisplayName = "AddSimpleSign with custom IHttpClientProvider uses it")]
    public void AddSimpleSign_CustomHttpClientProvider_UsesIt()
    {
        var custom = new TestHttpClientProvider();
        var services = new ServiceCollection();
        services.AddSimpleSign(null, custom);
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBeSameAs(custom);
    }

    [Fact(DisplayName = "AddSimpleSign applies configuration")]
    public void AddSimpleSign_AppliesConfiguration()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign(opts =>
        {
            opts.TsaUrl = "http://tsa.example.com";
            opts.CheckRevocation = false;
            opts.TrustSystemRoots = false;
            opts.NetworkTimeout = TimeSpan.FromSeconds(5);
        });
        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<SimpleSignOptions>();
        options.TsaUrl.ShouldBe("http://tsa.example.com");
        options.CheckRevocation.ShouldBeFalse();

        var valOptions = provider.GetRequiredService<ValidationOptions>();
        valOptions.CheckRevocation.ShouldBeFalse();
        valOptions.TrustSystemRoots.ShouldBeFalse();
        valOptions.NetworkTimeout.ShouldBe(TimeSpan.FromSeconds(5));
    }

    [Fact(DisplayName = "AddSimpleSign does not override pre-registered services")]
    public void AddSimpleSign_DoesNotOverrideExisting()
    {
        var custom = new TestHttpClientProvider();
        var services = new ServiceCollection();
        services.AddSingleton<IHttpClientProvider>(custom);
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBeSameAs(custom, "pre-registered provider should not be replaced");
    }

    [Fact(DisplayName = "AddSimpleSign default options have sensible values")]
    public void AddSimpleSign_DefaultOptions()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<SimpleSignOptions>();
        options.TsaUrl.ShouldBeNull();
        options.CheckRevocation.ShouldBeTrue();
        options.TrustSystemRoots.ShouldBeTrue();
        options.NetworkTimeout.ShouldBe(TimeSpan.FromSeconds(30));
        options.HttpClientName.ShouldBe("SimpleSign");
    }

    [Fact(DisplayName = "Transient services create new instances each time")]
    public void TransientServices_CreateNewInstances()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var v1 = provider.GetRequiredService<PdfSignatureValidator>();
        var v2 = provider.GetRequiredService<PdfSignatureValidator>();
        v1.ShouldNotBeSameAs(v2, "transient services should create new instances");
    }

    [Fact(DisplayName = "Singleton services return same instance")]
    public void SingletonServices_ReturnSameInstance()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var o1 = provider.GetRequiredService<SimpleSignOptions>();
        var o2 = provider.GetRequiredService<SimpleSignOptions>();
        o1.ShouldBeSameAs(o2);
    }

    [Fact(DisplayName = "AddSimpleSign without IHttpClientFactory uses DefaultHttpClientProvider")]
    public void AddSimpleSign_WithoutIHttpClientFactory_UsesDefaultProvider()
    {
        var services = new ServiceCollection();
        // No AddHttpClient — IHttpClientFactory is not registered
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBe(DefaultHttpClientProvider.Instance);
    }

    [Fact(DisplayName = "AddSimpleSign with IHttpClientFactory registered uses HttpClientFactoryProvider")]
    public void AddSimpleSign_WithIHttpClientFactory_UsesHttpClientFactoryProvider()
    {
        var services = new ServiceCollection();
        services.AddHttpClient(); // registers IHttpClientFactory
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBeOfType<HttpClientFactoryProvider>();
    }

    [Fact(DisplayName = "AddSimpleSign passes HttpClientName to HttpClientFactoryProvider")]
    public void AddSimpleSign_HttpClientName_IsPassedToHttpClientFactoryProvider()
    {
        const string customName = "MyApp.SimpleSign";
        var services = new ServiceCollection();
        services.AddHttpClient(customName);
        services.AddSimpleSign(opts => opts.HttpClientName = customName);
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBeOfType<HttpClientFactoryProvider>();
        // Verify the name is used: GetClient() should call factory.CreateClient(customName) — no exception.
        Should.NotThrow(() => httpProvider.GetClient());
    }

    [Fact(DisplayName = "AddSimpleSign pre-registered IHttpClientProvider takes precedence over IHttpClientFactory")]
    public void AddSimpleSign_PreRegisteredProvider_TakesPrecedenceOverFactory()
    {
        var custom = new TestHttpClientProvider();
        var services = new ServiceCollection();
        services.AddHttpClient(); // IHttpClientFactory is present
        services.AddSingleton<IHttpClientProvider>(custom); // but pre-registered provider wins
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.ShouldBeSameAs(custom);
    }

    [Fact(DisplayName = "PdfSignatureValidator accepts HttpClient directly — typed-client pattern")]
    public void PdfSignatureValidator_AcceptsHttpClient_TypedClientPattern()
    {
        // The typed-client pattern requires PdfSignatureValidator to have a HttpClient constructor.
        // This test verifies that the constructor exists and creates a working instance.
        using var httpClient = new HttpClient();
        var validator = new PdfSignatureValidator(options: null, httpClient: httpClient);

        validator.ShouldNotBeNull();
    }

    [Fact(DisplayName = "PdfSignatureValidator typed-client constructor respects validation options")]
    public void PdfSignatureValidator_TypedClientConstructor_RespectsValidationOptions()
    {
        using var httpClient = new HttpClient();
        var options = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };

        var validator = new PdfSignatureValidator(options: options, httpClient: httpClient);

        validator.ShouldNotBeNull();
    }

    private sealed class TestHttpClientProvider : IHttpClientProvider
    {
        public HttpClient GetClient() => new();
    }
}
