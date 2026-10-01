using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Validation;

/// <summary>Checks whether embedded revocation evidence covers each supplied non-root certificate.</summary>
public static class EmbeddedRevocationEvidence
{
    /// <summary>
    /// Checks applicable, signed and current OCSP or CRL evidence for every non-self-signed
    /// certificate. This checks evidence integrity and coverage, not certificate-path trust.
    /// </summary>
    public static bool CoversAll(
        IReadOnlyList<X509Certificate2> certificates,
        IReadOnlyList<byte[]> ocspResponses,
        IReadOnlyList<byte[]> crls,
        DateTimeOffset validationTime,
        IOcspClient ocspClient)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(ocspResponses);
        ArgumentNullException.ThrowIfNull(crls);
        ArgumentNullException.ThrowIfNull(ocspClient);

        bool hasRequiredCertificate = false;
        foreach (var certificate in certificates)
        {
            if (certificate.IsSelfSigned())
            {
                continue;
            }

            hasRequiredCertificate = true;
            var issuer = certificates.FindIssuerOf(certificate);
            if (issuer is null)
            {
                return false;
            }

            if (!CoversCertificate(certificate, issuer, ocspResponses, crls, validationTime, ocspClient))
            {
                return false;
            }
        }

        return hasRequiredCertificate;
    }

    /// <summary>Checks embedded evidence for one certificate using its known issuer.</summary>
    public static bool CoversCertificate(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        IReadOnlyList<byte[]> ocspResponses,
        IReadOnlyList<byte[]> crls,
        DateTimeOffset validationTime,
        IOcspClient ocspClient)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(ocspResponses);
        ArgumentNullException.ThrowIfNull(crls);
        ArgumentNullException.ThrowIfNull(ocspClient);

        bool covered = false;
        foreach (var response in ocspResponses)
        {
            try
            {
                bool? status = ocspClient.CheckEmbeddedOcspResponse(
                    certificate, issuer, response, validationTime);
                if (status == false)
                {
                    return false;
                }

                if (status == true)
                {
                    covered = true;
                }
            }
            catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException or InvalidOperationException)
            {
                // An unrelated or invalid response cannot cover this certificate.
            }
        }

        foreach (var crl in crls)
        {
            try
            {
                if (!HasBoundedCrlInterval(crl, validationTime))
                {
                    continue;
                }

                bool? isRevoked = CrlClient.IsSerialInCrl(
                    certificate, crl, issuer, signingTime: validationTime);
                if (isRevoked == true)
                {
                    return false;
                }

                if (isRevoked == false)
                {
                    covered = true;
                }
            }
            catch (CryptographicException)
            {
                // Invalid CRL signature or issuer key.
            }
        }

        return covered;
    }

    private static bool HasBoundedCrlInterval(byte[] crl, DateTimeOffset validationTime)
    {
        try
        {
            var reader = new AsnReader(crl, AsnEncodingRules.BER);
            var certificateList = reader.ReadSequence();
            var tbs = certificateList.ReadSequence();
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                _ = tbs.ReadInteger();
            }

            _ = tbs.ReadEncodedValue(); // signature algorithm
            _ = tbs.ReadEncodedValue(); // issuer
            var thisUpdate = ReadCrlTime(tbs);
            var nextUpdate = ReadCrlTime(tbs);
            return thisUpdate <= validationTime && validationTime <= nextUpdate;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static DateTimeOffset ReadCrlTime(AsnReader reader)
    {
        var tag = reader.PeekTag();
        return tag.TagValue == (int)UniversalTagNumber.UtcTime
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
    }
}
