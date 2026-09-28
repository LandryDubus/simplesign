using System.Formats.Asn1;
using System.Security.Cryptography;
using SimpleSign.Core.Constants;

namespace SimpleSign.CAdES;

/// <summary>Builds the ETSI EN 319 122-1 archive-time-stamp-v3 input and ATSHashIndexV3.</summary>
internal static class CadesArchiveTimestampBuilder
{
    internal sealed record ArchiveTimestampInput(byte[] DataToTimestamp, byte[] AtsHashIndex);

    internal static ArchiveTimestampInput Build(
        byte[] cms,
        ReadOnlySpan<byte> signedContent,
        HashAlgorithmName hashAlgorithm,
        bool excludeArchiveTimestamp = false)
    {
        ArgumentNullException.ThrowIfNull(cms);

        var reader = new AsnReader(cms, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        if (contentType != Oids.SignedData)
        {
            throw new InvalidDataException("CAdES archive timestamp input is not CMS SignedData.");
        }

        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadSetOf();

        var encapContentInfo = signedData.ReadSequence();
        byte[] encodedContentType = encapContentInfo.ReadEncodedValue().ToArray();

        var certificateHashes = new List<byte[]>();
        if (signedData.HasData
            && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certificates = signedData.ReadSetOf(
                skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (certificates.HasData)
            {
                certificateHashes.Add(Hash(certificates.ReadEncodedValue().Span, hashAlgorithm));
            }
        }

        var crlHashes = new List<byte[]>();
        if (signedData.HasData
            && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            var crls = signedData.ReadSetOf(
                skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (crls.HasData)
            {
                crlHashes.Add(Hash(crls.ReadEncodedValue().Span, hashAlgorithm));
            }
        }

        var signerInfos = signedData.ReadSetOf(skipSortOrderValidation: true);
        var signerInfo = signerInfos.ReadSequence();
        var protectedSignerFields = new List<byte[]>(6)
        {
            signerInfo.ReadEncodedValue().ToArray(),
            signerInfo.ReadEncodedValue().ToArray(),
            signerInfo.ReadEncodedValue().ToArray()
        };

        if (signerInfo.HasData
            && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            protectedSignerFields.Add(signerInfo.ReadEncodedValue().ToArray());
        }

        protectedSignerFields.Add(signerInfo.ReadEncodedValue().ToArray());
        protectedSignerFields.Add(signerInfo.ReadEncodedValue().ToArray());

        var unsignedAttributeValueHashes = new List<byte[]>();
        if (signerInfo.HasData
            && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            var unsignedAttributes = signerInfo.ReadSetOf(
                skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (unsignedAttributes.HasData)
            {
                var attribute = unsignedAttributes.ReadSequence();
                byte[] encodedAttributeType = attribute.ReadEncodedValue().ToArray();
                if (excludeArchiveTimestamp
                    && new AsnReader(encodedAttributeType, AsnEncodingRules.BER)
                        .ReadObjectIdentifier() == Oids.ArchiveTimeStamp)
                {
                    continue;
                }
                var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                while (values.HasData)
                {
                    byte[] encodedValue = values.ReadEncodedValue().ToArray();
                    unsignedAttributeValueHashes.Add(Hash(
                        Concat(encodedAttributeType, encodedValue),
                        hashAlgorithm));
                }
            }
        }

        byte[] atsHashIndex = EncodeAtsHashIndex(
            hashAlgorithm,
            certificateHashes,
            crlHashes,
            unsignedAttributeValueHashes);

        using var timestampInput = new MemoryStream();
        timestampInput.Write(encodedContentType);
        timestampInput.Write(Hash(signedContent, hashAlgorithm));
        foreach (byte[] field in protectedSignerFields)
        {
            timestampInput.Write(field);
        }

        timestampInput.Write(atsHashIndex);
        return new ArchiveTimestampInput(timestampInput.ToArray(), atsHashIndex);
    }

    private static byte[] EncodeAtsHashIndex(
        HashAlgorithmName hashAlgorithm,
        IReadOnlyList<byte[]> certificateHashes,
        IReadOnlyList<byte[]> crlHashes,
        IReadOnlyList<byte[]> unsignedAttributeValueHashes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(GetHashOid(hashAlgorithm));
                if (hashAlgorithm != HashAlgorithmName.SHA3_256
                    && hashAlgorithm != HashAlgorithmName.SHA3_384
                    && hashAlgorithm != HashAlgorithmName.SHA3_512)
                {
                    writer.WriteNull();
                }
            }

            WriteHashSequence(writer, certificateHashes);
            WriteHashSequence(writer, crlHashes);
            WriteHashSequence(writer, unsignedAttributeValueHashes);
        }

        return writer.Encode();
    }

    private static void WriteHashSequence(AsnWriter writer, IReadOnlyList<byte[]> hashes)
    {
        using (writer.PushSequence())
        {
            foreach (byte[] hash in hashes)
            {
                writer.WriteOctetString(hash);
            }
        }
    }

    private static byte[] Hash(ReadOnlySpan<byte> data, HashAlgorithmName algorithm) => algorithm switch
    {
        _ when algorithm == HashAlgorithmName.SHA256 => SHA256.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA384 => SHA384.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA512 => SHA512.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA3_256 => SHA3_256.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA3_384 => SHA3_384.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA3_512 => SHA3_512.HashData(data),
        _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported.")
    };

    private static string GetHashOid(HashAlgorithmName algorithm) => algorithm switch
    {
        _ when algorithm == HashAlgorithmName.SHA256 => Oids.Sha256,
        _ when algorithm == HashAlgorithmName.SHA384 => Oids.Sha384,
        _ when algorithm == HashAlgorithmName.SHA512 => Oids.Sha512,
        _ when algorithm == HashAlgorithmName.SHA3_256 => Oids.Sha3_256,
        _ when algorithm == HashAlgorithmName.SHA3_384 => Oids.Sha3_384,
        _ when algorithm == HashAlgorithmName.SHA3_512 => Oids.Sha3_512,
        _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported.")
    };

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }
}
