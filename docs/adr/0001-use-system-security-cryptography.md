# ADR 0001: Use System.Security.Cryptography (No BouncyCastle)

**Status:** Accepted (permanent)

**Context:**
Digital signature libraries in .NET traditionally depend on BouncyCastle (Org.BouncyCastle) for cryptographic operations, ASN.1 parsing, and CMS/PKCS#7 construction. This dependency adds significant size to the deployment footprint, creates version conflicts with other libraries, and introduces AOT compatibility challenges.

**Decision:**
SimpleSign uses exclusively `System.Security.Cryptography` from the .NET BCL. This includes:

- `RSA`, `ECDsa` for signing and verification
- `System.Formats.Asn1.AsnWriter`/`AsnReader` for DER encoding
- `X509Certificate2` for certificate operations
- `SHA256`, `SHA384`, `SHA512`, `SHA3_*` (NET9+) for hashing

No reference to `Org.BouncyCastle` exists anywhere in the codebase.

**Consequences:**
- Zero external cryptographic dependencies
- Full AOT/NativeAOT compatibility
- Smaller deployment footprint
- Automatic security updates via .NET runtime patches
- Higher development effort for CMS ASN.1 construction (must build manually)
- Limited to algorithms available in the BCL (no Brainpool, no GOST, no custom curves)
- EdDSA depends on runtime support (.NET 9+)

**Status:** This decision is permanent. No BouncyCastle dependency will be added.
