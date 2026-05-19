using System.Net;

namespace SimpleSign.Brasil.Tests;

internal sealed class FakeHttpHandler(HttpStatusCode status) : HttpMessageHandler()
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(status));
}
