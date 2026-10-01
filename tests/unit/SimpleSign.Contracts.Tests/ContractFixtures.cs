using System.Net;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.TestHelpers;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Shared cross-format helpers for the signing contract tests.
/// </summary>
internal static class ContractFixtures
{
    internal static readonly byte[] XmlDocument = "<?xml version=\"1.0\"?><root><data>contract test</data></root>"u8.ToArray();

    internal static readonly byte[] BinaryContent = "Cross-format contract test content"u8.ToArray();

    internal static X509Certificate2 CreateSignerCertificate(string subject = "CN=Contract Signer, O=Tests") =>
        TestCertificateFactory.CreateSelfSignedCert(subject);

    internal static HttpMessageHandler BuildMockTsaHandler() => MockTimestampAuthority.CreateHandler();

    internal static HttpClient BuildMockTsaClient() => new(BuildMockTsaHandler());

    internal static HttpClient BuildMockTsaClient(Action<byte[]> tokenObserver) =>
        MockTimestampAuthority.CreateClient(tokenObserver);

    internal static HttpClient BuildFailingClient() => MockHttpHandler.Failing();

}

/// <summary>Builds an <see cref="HttpClient"/> that serves signed CRLs for the synthetic PKI.</summary>
internal static class TestRevocationClient
{
    internal static HttpClient BuildFor(SyntheticPki pki) =>
        new(new MockHttpHandler(request =>
        {
            byte[] crl = request.RequestUri?.Query.Contains("issuer=root", StringComparison.Ordinal) == true
                ? SyntheticPki.BuildGoodCrl(pki.RootCa)
                : SyntheticPki.BuildGoodCrl(pki.IntermediateCa);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(crl)
            });
        }));
}
