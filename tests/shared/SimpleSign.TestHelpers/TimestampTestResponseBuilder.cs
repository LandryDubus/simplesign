using System.Formats.Asn1;
using System.Security.Cryptography;

namespace SimpleSign.TestHelpers;

/// <summary>Builds structurally valid RFC 3161 responses for tests that do not need TSA signature validation.</summary>
public static class TimestampTestResponseBuilder
{
    /// <summary>Builds a granted response bound to the hash algorithm, imprint, and nonce in a timestamp request.</summary>
    /// <param name="requestBytes">DER-encoded RFC 3161 timestamp request.</param>
    /// <returns>A DER-encoded granted timestamp response.</returns>
    public static byte[] CreateForRequest(byte[] requestBytes)
    {
        ArgumentNullException.ThrowIfNull(requestBytes);

        var requestReader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var request = requestReader.ReadSequence();
        _ = request.ReadInteger();
        var imprint = request.ReadSequence();
        var algorithm = imprint.ReadSequence();
        string hashOid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
        {
            _ = algorithm.ReadEncodedValue();
        }

        byte[] hash = imprint.ReadOctetString();
        var nonce = request.ReadInteger();
        byte[] token = BuildToken(hashOid, hash, nonce);

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

    /// <summary>Builds a timestamp token over a supplied datum for direct <c>ITimestampClient</c> test doubles.</summary>
    /// <param name="dataToTimestamp">The raw bytes the client was asked to timestamp.</param>
    /// <param name="hashAlgorithm">The requested message-imprint hash algorithm.</param>
    /// <returns>A structurally valid RFC 3161 CMS token.</returns>
    public static byte[] CreateTokenForData(ReadOnlySpan<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm)
    {
        (string oid, byte[] hash) = hashAlgorithm switch
        {
            _ when hashAlgorithm == HashAlgorithmName.SHA256 => ("2.16.840.1.101.3.4.2.1", SHA256.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA384 => ("2.16.840.1.101.3.4.2.2", SHA384.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA512 => ("2.16.840.1.101.3.4.2.3", SHA512.HashData(dataToTimestamp)),
            _ => throw new NotSupportedException($"Test timestamp token does not support '{hashAlgorithm.Name}'.")
        };

        return BuildToken(oid, hash, System.Numerics.BigInteger.Zero);
    }

    private static byte[] BuildToken(string hashOid, byte[] hash, System.Numerics.BigInteger nonce)
    {
        var tstInfoWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tstInfoWriter.PushSequence())
        {
            tstInfoWriter.WriteInteger(1);
            tstInfoWriter.WriteObjectIdentifier("1.2.3.4");
            using (tstInfoWriter.PushSequence())
            {
                using (tstInfoWriter.PushSequence())
                {
                    tstInfoWriter.WriteObjectIdentifier(hashOid);
                    tstInfoWriter.WriteNull();
                }

                tstInfoWriter.WriteOctetString(hash);
            }

            tstInfoWriter.WriteInteger(1);
            tstInfoWriter.WriteGeneralizedTime(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
            tstInfoWriter.WriteInteger(nonce);
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteInteger(1);
                    using (writer.PushSetOf())
                    {
                    }

                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4");
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                        {
                            writer.WriteOctetString(tstInfoWriter.Encode());
                        }
                    }

                    using (writer.PushSetOf())
                    {
                        // A minimally encoded SignerInfo lets archive-timestamp tests append
                        // ETSI unsigned attributes to the RFC 3161 token. Its signature is not
                        // used by these structural test fixtures.
                        using (writer.PushSequence())
                        {
                            writer.WriteInteger(1);
                            using (writer.PushSequence())
                            {
                                using (writer.PushSequence())
                                {
                                }

                                writer.WriteInteger(1);
                            }

                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier(hashOid);
                                writer.WriteNull();
                            }

                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                                writer.WriteNull();
                            }

                            writer.WriteOctetString([0]);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }
}
