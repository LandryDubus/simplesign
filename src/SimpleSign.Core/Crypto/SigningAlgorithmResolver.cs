using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Crypto;

/// <summary>Resolves and validates signing algorithms consistently across AdES formats.</summary>
internal static class SigningAlgorithmResolver
{
    internal static HashAlgorithmName ResolveHashAlgorithm(
        HashAlgorithmName configuredHash,
        bool hashExplicitlySet,
        string? signatureAlgorithmOid)
    {
        HashAlgorithmName? oidHash = TryGetCombinedOidHash(signatureAlgorithmOid);
        if (oidHash is null)
        {
            return configuredHash;
        }

        if (hashExplicitlySet && configuredHash != oidHash.Value)
        {
            throw new SigningException(
                $"Signature algorithm '{signatureAlgorithmOid}' requires {oidHash.Value.Name}, " +
                $"but {configuredHash.Name} was explicitly configured.",
                SigningErrorReason.AlgorithmIncompatible);
        }

        return oidHash.Value;
    }

    internal static void ValidateCompatibility(X509Certificate2 certificate, string signatureAlgorithmOid)
    {
        try
        {
            CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, signatureAlgorithmOid);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            throw new SigningException(ex.Message, SigningErrorReason.AlgorithmIncompatible, ex);
        }
    }

    private static HashAlgorithmName? TryGetCombinedOidHash(string? signatureAlgorithmOid) =>
        signatureAlgorithmOid switch
        {
            Oids.RsaSha256 or Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
            Oids.RsaSha384 or Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
            Oids.RsaSha512 or Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
            Oids.RsaSha3_256 or Oids.EcdsaSha3_256 => HashAlgorithmName.SHA3_256,
            Oids.RsaSha3_384 or Oids.EcdsaSha3_384 => HashAlgorithmName.SHA3_384,
            Oids.RsaSha3_512 or Oids.EcdsaSha3_512 => HashAlgorithmName.SHA3_512,
            Oids.RsaSha1 => HashAlgorithmName.SHA1,
            _ => null
        };
}
