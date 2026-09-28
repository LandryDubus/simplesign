using System.Formats.Asn1;
using System.Net;
using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.TestHelpers;

/// <summary>Builds RFC 3161-shaped responses bound to the request received by a mock TSA.</summary>
public static class MockTimestampAuthority
{
    private static readonly RSA TsaKey = RSA.Create(2048);
    private static readonly X509Certificate2 TsaCertificate = CreateTsaCertificate();

    private static X509Certificate2 CreateTsaCertificate()
    {
        var request = new CertificateRequest("CN=SimpleSign Test TSA", TsaKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var usages = new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, critical: true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
    /// <summary>Creates an HTTP client whose timestamp responses echo each request's imprint and nonce.</summary>
    public static HttpClient CreateClient(Action<byte[]>? tokenObserver = null) => new(CreateHandler(tokenObserver));

    /// <summary>Creates a handler whose timestamp responses echo each request's imprint and nonce.</summary>
    public static HttpMessageHandler CreateHandler(Action<byte[]>? tokenObserver = null) => new MockHttpHandler(async request =>
    {
        if (request.Method == HttpMethod.Get)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([0x30, 0x00])
            };
        }

        byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
        byte[] responseBytes = CreateResponse(requestBytes);
        if (tokenObserver is not null)
        {
            var responseReader = new AsnReader(responseBytes, AsnEncodingRules.DER).ReadSequence();
            _ = responseReader.ReadSequence();
            tokenObserver(responseReader.ReadEncodedValue().ToArray());
        }

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(responseBytes)
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
        return response;
    });

    /// <summary>Creates a response for a DER-encoded TimeStampReq.</summary>
    public static byte[] CreateResponse(
        byte[] requestBytes,
        string? hashAlgorithmOid = null,
        byte[]? hashedMessage = null,
        BigInteger? nonce = null,
        bool omitNonce = false,
        string? encapsulatedContentType = null)
    {
        ArgumentNullException.ThrowIfNull(requestBytes);

        var requestReader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var request = requestReader.ReadSequence();
        _ = request.ReadInteger();
        var requestImprint = request.ReadSequence();
        var requestAlgorithm = requestImprint.ReadSequence();
        string requestedHashOid = requestAlgorithm.ReadObjectIdentifier();
        if (requestAlgorithm.HasData)
        {
            _ = requestAlgorithm.ReadEncodedValue();
        }

        byte[] requestedHash = requestImprint.ReadOctetString();
        BigInteger requestedNonce = request.ReadInteger();

        string responseHashOid = hashAlgorithmOid ?? requestedHashOid;
        byte[] responseHash = hashedMessage ?? requestedHash;
        BigInteger responseNonce = nonce ?? requestedNonce;
        byte[] tstInfo = BuildTstInfo(responseHashOid, responseHash, responseNonce, omitNonce);
        byte[] token = BuildToken(tstInfo, encapsulatedContentType ?? Oids.TimestampInfoContentType);

        var responseWriter = new AsnWriter(AsnEncodingRules.DER);
        using (responseWriter.PushSequence())
        {
            using (responseWriter.PushSequence())
            {
                responseWriter.WriteInteger(0);
            }

            responseWriter.WriteEncodedValue(token);
        }

        return responseWriter.Encode();
    }

    private static byte[] BuildTstInfo(
        string hashAlgorithmOid,
        byte[] hashedMessage,
        BigInteger nonce,
        bool omitNonce)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteObjectIdentifier("1.2.3.4.1");
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(hashAlgorithmOid);
                    if (hashAlgorithmOid is not (Oids.Sha3_256 or Oids.Sha3_384 or Oids.Sha3_512))
                    {
                        writer.WriteNull();
                    }
                }

                writer.WriteOctetString(hashedMessage);
            }

            writer.WriteInteger(1);
            writer.WriteGeneralizedTime(DateTimeOffset.UtcNow, omitFractionalSeconds: true);
            if (!omitNonce)
            {
                writer.WriteInteger(nonce);
            }
        }

        return writer.Encode();
    }

    private static byte[] BuildToken(
        byte[] tstInfo,
        string encapsulatedContentType)
    {
        var signedAttributesWriter = new AsnWriter(AsnEncodingRules.DER);
        using (signedAttributesWriter.PushSetOf())
        {
            using (signedAttributesWriter.PushSequence())
            {
                signedAttributesWriter.WriteObjectIdentifier(Oids.ContentType);
                using (signedAttributesWriter.PushSetOf())
                {
                    signedAttributesWriter.WriteObjectIdentifier(encapsulatedContentType);
                }
            }
            using (signedAttributesWriter.PushSequence())
            {
                signedAttributesWriter.WriteObjectIdentifier(Oids.MessageDigest);
                using (signedAttributesWriter.PushSetOf())
                {
                    signedAttributesWriter.WriteOctetString(SHA256.HashData(tstInfo));
                }
            }
            using (signedAttributesWriter.PushSequence())
            {
                signedAttributesWriter.WriteObjectIdentifier(Oids.SigningCertificateV2);
                using (signedAttributesWriter.PushSetOf())
                using (signedAttributesWriter.PushSequence())
                using (signedAttributesWriter.PushSequence())
                using (signedAttributesWriter.PushSequence())
                {
                    signedAttributesWriter.WriteOctetString(SHA256.HashData(TsaCertificate.RawData));
                }
            }
        }
        byte[] signedAttributes = signedAttributesWriter.Encode();
        byte[] signature = TsaKey.SignData(signedAttributes,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signedAttributes[0] = 0xA0;

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oids.SignedData);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteInteger(3);
                    using (writer.PushSetOf())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(Oids.Sha256);
                            writer.WriteNull();
                        }
                    }

                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(encapsulatedContentType);
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                        {
                            writer.WriteOctetString(tstInfo);
                        }
                    }

                    using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        writer.WriteEncodedValue(TsaCertificate.RawData);
                    }

                    using (writer.PushSetOf())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteInteger(1);
                            using (writer.PushSequence())
                            {
                                writer.WriteEncodedValue(TsaCertificate.IssuerName.RawData);
                                writer.WriteIntegerUnsigned(TsaCertificate.SerialNumberBytes.Span);
                            }

                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier(Oids.Sha256);
                                writer.WriteNull();
                            }

                            writer.WriteEncodedValue(signedAttributes);

                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier(Oids.RsaSha256);
                                writer.WriteNull();
                            }

                            writer.WriteOctetString(signature);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }
}
