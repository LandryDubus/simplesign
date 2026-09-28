using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Cross-format contract tests for the external signing request contract and
/// execution-time algorithm resolution (order independence).
/// </summary>
public sealed class ExternalSignerContractTests
{
    [Theory]
    [InlineData("pades", ExternalSigningPayloadKind.CmsSignedAttributes)]
    [InlineData("cades", ExternalSigningPayloadKind.CmsSignedAttributes)]
    [InlineData("xades", ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo)]
    public async Task ExternalSigner_ReceivesPayloadKindAlgorithmsAndOperationId(
        string format, ExternalSigningPayloadKind expectedPayloadKind)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithExternalSigner(cert, signer)
                    .WithHashAlgorithm(HashAlgorithmName.SHA384)
                    .WithOperationId("op-123")
                    .SignAsync();
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithExternalSigner(cert, signer)
                    .WithHashAlgorithm(HashAlgorithmName.SHA384)
                    .WithOperationId("op-123")
                    .SignAsync();
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithExternalSigner(cert, signer)
                    .WithHashAlgorithm(HashAlgorithmName.SHA384)
                    .WithOperationId("op-123")
                    .SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }

        var request = signer.LastRequest.ShouldNotBeNull();
        request.PayloadKind.ShouldBe(expectedPayloadKind);
        request.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA384);
        request.SignatureAlgorithmOid.ShouldBe("1.2.840.113549.1.1.12"); // RSA-SHA384
        request.OperationId.ShouldBe("op-123");
        request.DataToSign.Length.ShouldBeGreaterThan(0);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task HashAlgorithmSetBeforeOrAfterExternalSigner_ProducesSameRequest(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var first = new CapturingSigner(cert);
        var second = new CapturingSigner(cert);

        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithExternalSigner(cert, first)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .SignAsync();
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .WithExternalSigner(cert, second)
                    .SignAsync();
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithExternalSigner(cert, first)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .SignAsync();
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .WithExternalSigner(cert, second)
                    .SignAsync();
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithExternalSigner(cert, first)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .SignAsync();
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .WithExternalSigner(cert, second)
                    .SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }

        first.LastRequest.ShouldNotBeNull();
        second.LastRequest.ShouldNotBeNull();
        first.LastRequest.HashAlgorithm.ShouldBe(second.LastRequest.HashAlgorithm);
        first.LastRequest.SignatureAlgorithmOid.ShouldBe(second.LastRequest.SignatureAlgorithmOid);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task CombinedSignatureOid_InfersHashOnAllFormats(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        await SignExternalAsync(format, cert, signer, Oids.RsaSha512);

        signer.LastRequest.ShouldNotBeNull().HashAlgorithm.ShouldBe(HashAlgorithmName.SHA512);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task ConflictingHashAndCombinedSignatureOid_IsRejected(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        var exception = await Should.ThrowAsync<SigningException>(() =>
            SignExternalAsync(format, cert, signer, Oids.RsaSha512, HashAlgorithmName.SHA256));

        exception.Reason.ShouldBe(SigningErrorReason.AlgorithmIncompatible);
        signer.LastRequest.ShouldBeNull();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task RsaPss_RequestCarriesResolvedParameters(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        await SignExternalAsync(format, cert, signer, Oids.RsaPss, HashAlgorithmName.SHA384);

        var parameters = signer.LastRequest.ShouldNotBeNull().RsaPssParameters.ShouldNotBeNull();
        parameters.MaskGenerationHashAlgorithm.ShouldBe(HashAlgorithmName.SHA384);
        parameters.SaltLength.ShouldBe(48);
        parameters.TrailerField.ShouldBe(1);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task InvalidRawExternalSignature_IsRejectedBeforePackaging(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new InvalidSigner();

        var exception = await Should.ThrowAsync<SigningException>(() =>
            SignExternalAsync(format, cert, signer));

        exception.Reason.ShouldBe(SigningErrorReason.AlgorithmIncompatible);
    }

    private static async Task SignExternalAsync(
        string format,
        X509Certificate2 certificate,
        IExternalSigner signer,
        string? signatureAlgorithmOid = null,
        HashAlgorithmName? hashAlgorithm = null)
    {
        switch (format)
        {
            case "pades":
                {
                    var builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                        .WithExternalSigner(certificate, signer);
                    if (signatureAlgorithmOid is not null)
                    {
                        builder = builder.WithSignatureAlgorithm(signatureAlgorithmOid);
                    }
                    if (hashAlgorithm is not null)
                    {
                        builder = builder.WithHashAlgorithm(hashAlgorithm.Value);
                    }
                    await builder.SignAsync();
                    break;
                }
            case "cades":
                {
                    var builder = CadesSigner.Document(ContractFixtures.BinaryContent)
                        .WithExternalSigner(certificate, signer);
                    if (signatureAlgorithmOid is not null)
                    {
                        builder = builder.WithSignatureAlgorithm(signatureAlgorithmOid);
                    }
                    if (hashAlgorithm is not null)
                    {
                        builder = builder.WithHashAlgorithm(hashAlgorithm.Value);
                    }
                    await builder.SignAsync();
                    break;
                }
            case "xades":
                {
                    var builder = XadesSigner.Document(ContractFixtures.XmlDocument)
                        .WithExternalSigner(certificate, signer);
                    if (signatureAlgorithmOid is not null)
                    {
                        builder = builder.WithSignatureAlgorithm(signatureAlgorithmOid);
                    }
                    if (hashAlgorithm is not null)
                    {
                        builder = builder.WithHashAlgorithm(hashAlgorithm.Value);
                    }
                    await builder.SignAsync();
                    break;
                }
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    private sealed class CapturingSigner : IExternalSigner
    {
        private readonly X509Certificate2 _certificate;

        public CapturingSigner(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public ExternalSigningRequest? LastRequest { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            using var rsa = _certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Signer certificate has no private key.");
            RSASignaturePadding padding = request.SignatureAlgorithmOid == SimpleSign.Core.Constants.Oids.RsaPss
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1;
            byte[] signature = rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, padding);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(signature);
        }
    }

    private sealed class InvalidSigner : IExternalSigner
    {
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(new byte[256]);
    }
}
