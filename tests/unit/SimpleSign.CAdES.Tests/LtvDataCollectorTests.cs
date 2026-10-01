using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Shouldly;
using Xunit;

namespace SimpleSign.CAdES.Tests;

public sealed class LtvDataCollectorTests : IDisposable
{
    private readonly SyntheticPki _pki;
    private readonly X509Certificate2 _selfSigned;

    public LtvDataCollectorTests()
    {
        _pki = new SyntheticPki("http://localhost/crl", "http://localhost/ocsp");
        _selfSigned = TestCertificateFactory.CreateSelfSignedCert();
    }

    public void Dispose()
    {
        _pki.Dispose();
        _selfSigned.Dispose();
    }

    [Fact]
    public void LtvCollectionResult_Parameters_AreStoredCorrectly()
    {
        var certs = new byte[][] { [1, 2, 3] };
        var ocsp = new byte[][] { [4, 5, 6] };
        var crls = new byte[][] { [7, 8, 9] };

        var result = new LtvCollectionResult(certs, ocsp, crls);

        result.CertificateRawData.ShouldHaveSingleItem();
        result.CertificateRawData[0].ShouldBe([1, 2, 3]);
        result.OcspResponses.ShouldHaveSingleItem();
        result.OcspResponses[0].ShouldBe([4, 5, 6]);
        result.Crls.ShouldHaveSingleItem();
        result.Crls[0].ShouldBe([7, 8, 9]);
    }

    [Fact]
    public async Task CollectAsync_WithCertWithoutRevocationUrls_ReturnsEmptyOcspAndCrls()
    {
        using var httpClient = new HttpClient(new MockHttpHandler(_ =>
            throw new HttpRequestException()));

        var result = await LtvDataCollector.CollectAsync(httpClient, _selfSigned, null, null);

        result.CertificateRawData.ShouldHaveSingleItem();
        result.CertificateRawData[0].ShouldBe(_selfSigned.RawData);
        result.OcspResponses.ShouldBeEmpty();
        result.Crls.ShouldBeEmpty();
    }

    [Fact]
    public async Task CollectAsync_WithRevocationUrls_FailingNetwork_ReturnsCertDataWithoutRevocation()
    {
        using var httpClient = MockHttpHandler.Failing();

        var result = await LtvDataCollector.CollectAsync(
            httpClient, _pki.Leaf, [_pki.IntermediateCa], null);

        result.CertificateRawData.ShouldNotBeEmpty();
        result.CertificateRawData.Count.ShouldBeGreaterThanOrEqualTo(2);
        result.OcspResponses.ShouldBeEmpty();
        result.Crls.ShouldBeEmpty();
    }

    [Fact]
    public async Task CollectAsync_NullSignerCert_ThrowsArgumentNullException()
    {
        using var httpClient = new HttpClient();

        var ex = await Should.ThrowAsync<ArgumentNullException>(
            () => LtvDataCollector.CollectAsync(httpClient, null!, null, null));

        ex.ParamName.ShouldBe("signerCert");
    }

    [Fact]
    public async Task CollectAsync_NullHttpClient_ThrowsArgumentNullException()
    {
        var ex = await Should.ThrowAsync<ArgumentNullException>(
            () => LtvDataCollector.CollectAsync(null!, _selfSigned, null, null));

        ex.ParamName.ShouldBe("httpClient");
    }

    [Fact]
    public async Task CollectAsync_WithChain_IncludesChainCertificates()
    {
        using var httpClient = MockHttpHandler.Failing();

        var result = await LtvDataCollector.CollectAsync(
            httpClient, _pki.Leaf, [_pki.IntermediateCa, _pki.RootCa], null);

        result.CertificateRawData.Count.ShouldBe(3);
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.Leaf.RawData));
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.IntermediateCa.RawData));
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.RootCa.RawData));
    }

    [Fact]
    public async Task CollectAsync_WithDuplicateCertInChain_RemovesDuplicates()
    {
        using var httpClient = MockHttpHandler.Failing();

        var result = await LtvDataCollector.CollectAsync(
            httpClient, _pki.Leaf, [_pki.Leaf, _pki.IntermediateCa], null);

        result.CertificateRawData.Count.ShouldBe(2);
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.Leaf.RawData));
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.IntermediateCa.RawData));
    }

    [Fact]
    public async Task CollectAsync_OcspFailureForLaterCertificate_UsesItsCrlFallback()
    {
        using var pki = new SyntheticPki(
            "http://crl.example.com/test.crl",
            "http://ocsp.example.com");
        using var httpClient = MockHttpHandler.ForGetBytes([0x30, 0x00]);
        var ocsp = new SequencedOcspClient();

        var result = await LtvDataCollector.CollectAsync(
            httpClient,
            pki.Leaf,
            [pki.IntermediateCa, pki.RootCa],
            null,
            ocsp);

        result.OcspResponses.ShouldHaveSingleItem();
        result.Crls.ShouldBeEmpty();
        result.HasCompleteRevocationData.ShouldBeFalse();
        result.CertificateStatuses.ShouldNotBeNull()
            .Where(status => status.RequiresRevocationData)
            .ShouldContain(status => !status.HasRevocationData);
    }

    [Fact]
    public async Task CollectAsync_CancellationDuringOcsp_Propagates()
    {
        using var httpClient = MockHttpHandler.Failing();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Should.ThrowAsync<OperationCanceledException>(() =>
            LtvDataCollector.CollectAsync(
                httpClient,
                _pki.Leaf,
                [_pki.IntermediateCa],
                null,
                new CancellingOcspClient(),
                cts.Token));
    }

    private sealed class SequencedOcspClient : IOcspClient
    {
        private int _calls;

        public Task<OcspFetchResult> FetchOcspResponseAsync(
            X509Certificate2 cert,
            X509Certificate2? issuerCert,
            string ocspUrl,
            CancellationToken ct)
        {
            _calls++;
            return _calls == 1
                ? Task.FromResult(new OcspFetchResult(true, [1, 2, 3], []))
                : throw new HttpRequestException("OCSP unavailable");
        }

        public Task<bool> CheckOcspAsync(X509Certificate2 cert, string ocspUrl, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<bool> CheckOcspWithChainAsync(
            X509Certificate2 cert,
            IReadOnlyList<X509Certificate2> chain,
            string ocspUrl,
            CancellationToken ct) => throw new NotSupportedException();

        public bool? CheckEmbeddedOcspResponse(
            X509Certificate2 cert,
            X509Certificate2? issuerCert,
            byte[] ocspResponseBytes,
            DateTimeOffset? signingTime) => true;
    }

    private sealed class CancellingOcspClient : IOcspClient
    {
        public Task<OcspFetchResult> FetchOcspResponseAsync(
            X509Certificate2 cert,
            X509Certificate2? issuerCert,
            string ocspUrl,
            CancellationToken ct) => Task.FromCanceled<OcspFetchResult>(ct);

        public Task<bool> CheckOcspAsync(X509Certificate2 cert, string ocspUrl, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<bool> CheckOcspWithChainAsync(
            X509Certificate2 cert,
            IReadOnlyList<X509Certificate2> chain,
            string ocspUrl,
            CancellationToken ct) => throw new NotSupportedException();

        public bool? CheckEmbeddedOcspResponse(
            X509Certificate2 cert,
            X509Certificate2? issuerCert,
            byte[] ocspResponseBytes,
            DateTimeOffset? signingTime) => throw new NotSupportedException();
    }
}
