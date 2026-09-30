using System.Net;
using SimpleSign.TestHelpers;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Builds an <see cref="HttpClient"/> that answers every request (CRL distribution
/// points, AIA) with the provided CRL bytes, so strict B-LT/B-LTA signing tests can
/// collect realistic revocation material without depending on public infrastructure.
/// </summary>
internal static class TestRevocation
{
    private const string LeafCrlUrl = "http://crl.example.com/leaf.crl";
    private const string IntermediateCrlUrl = "http://crl.example.com/intermediate.crl";

    internal static SyntheticPki CreatePki() => new(
        crlDistributionPoint: LeafCrlUrl,
        intermediateCrlDistributionPoint: IntermediateCrlUrl);

    internal static HttpClient BuildCrlClient(SyntheticPki pki)
    {
        ArgumentNullException.ThrowIfNull(pki);
        return new HttpClient(new RevocationRoutingHandler(
            pki.BuildLeafCrl(),
            pki.BuildIntermediateCrl()));
    }

    private sealed class RevocationRoutingHandler(
        byte[] leafCrl,
        byte[] intermediateCrl) : HttpMessageHandler
    {
        private readonly HttpClient _networkClient = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            string? requestUri = request.RequestUri?.ToString();
            if (string.Equals(requestUri, LeafCrlUrl, StringComparison.Ordinal))
            {
                return CrlResponse(leafCrl);
            }

            if (string.Equals(requestUri, IntermediateCrlUrl, StringComparison.Ordinal))
            {
                return CrlResponse(intermediateCrl);
            }

            using var forwardedRequest = await CloneRequestAsync(request, cancellationToken).ConfigureAwait(false);
            return await _networkClient.SendAsync(
                forwardedRequest,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _networkClient.Dispose();
            }

            base.Dispose(disposing);
        }

        private static HttpResponseMessage CrlResponse(byte[] crl) => new(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(crl)
        };

        private static async Task<HttpRequestMessage> CloneRequestAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri)
            {
                Version = request.Version,
                VersionPolicy = request.VersionPolicy,
            };

            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (request.Content is not null)
            {
                byte[] content = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                clone.Content = new ByteArrayContent(content);
                foreach (var header in request.Content.Headers)
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            return clone;
        }
    }
}
