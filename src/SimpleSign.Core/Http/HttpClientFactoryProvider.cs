namespace SimpleSign.Core.Http;

/// <summary>
/// <see cref="IHttpClientProvider"/> backed by <see cref="IHttpClientFactory"/>.
/// Each call to <see cref="GetClient"/> invokes <c>IHttpClientFactory.CreateClient(name)</c>,
/// which respects the named-client configuration and lifetime managed by the factory.
/// </summary>
/// <remarks>
/// <para>
/// This provider is automatically used when <c>IHttpClientFactory</c> is registered in the
/// dependency-injection container and no explicit <see cref="IHttpClientProvider"/> has been
/// supplied. The client name is taken from <c>SimpleSignOptions.HttpClientName</c>
/// (default: <c>"SimpleSign"</c>).
/// </para>
/// <para>
/// To configure the named pipeline in ASP.NET Core:
/// <code>
/// services.AddHttpClient("SimpleSign", client =>
/// {
///     client.Timeout = TimeSpan.FromSeconds(10);
/// });
/// services.AddSimpleSign();   // auto-wired: IHttpClientFactory is detected in the container
/// </code>
/// </para>
/// <para>
/// To use separate clients for TSA and revocation operations, supply an instance directly:
/// <code>
/// services.AddHttpClient("SimpleSign.Tsa", client =>
/// {
///     client.DefaultRequestHeaders.Authorization =
///         new AuthenticationHeaderValue("Bearer", token);
/// });
/// services.AddHttpClient("SimpleSign.Revocation");
///
/// var tsaClient        = httpClientFactory.CreateClient("SimpleSign.Tsa");
/// var revocationClient = httpClientFactory.CreateClient("SimpleSign.Revocation");
///
/// var signed = await SimpleSigner
///     .Document(pdf)
///     .WithCertificate(cert)
///     .WithTimestamp(tsaUrl, tsaClient)
///     .WithLtv()
///     .WithHttpClient(revocationClient)
///     .SignAsync();
/// </code>
/// </para>
/// </remarks>
public sealed class HttpClientFactoryProvider : IHttpClientProvider
{
    private readonly IHttpClientFactory _factory;
    private readonly string _clientName;

    /// <summary>
    /// Creates a provider that resolves named clients from <paramref name="factory"/>.
    /// </summary>
    /// <param name="factory">The <see cref="IHttpClientFactory"/> to delegate to.</param>
    /// <param name="clientName">
    /// Named-client key passed to <see cref="IHttpClientFactory.CreateClient(string)"/>.
    /// Defaults to <c>"SimpleSign"</c>.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="factory"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="clientName"/> is null or whitespace.</exception>
    public HttpClientFactoryProvider(IHttpClientFactory factory, string clientName = "SimpleSign")
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        _factory = factory;
        _clientName = clientName;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Calls <see cref="IHttpClientFactory.CreateClient(string)"/> on every invocation.
    /// The factory manages <see cref="HttpClient"/> lifetime and handler rotation.
    /// </remarks>
    public HttpClient GetClient() => _factory.CreateClient(_clientName);
}
