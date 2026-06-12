# ADR 0009: Country Extension / Plug-in Architecture

**Status:** Accepted

**Context:**
Digital signature regulations vary by country. Brazil has ICP-Brasil with 13 AC Raiz policies (AD-RB through AD-RA) and Gov.br with 4 assurance levels, plus the Lei 14.063 signature manifest. The European Union has the eIDAS Trusted List with national root stores. The United States has the FPKI trust framework. Each jurisdiction defines:
- Which root CAs are trusted (trust anchor lists)
- How certificate chains are validated beyond standard X.509 (policy OIDs, assurance levels)
- What metadata must be embedded in the signature (manifest attributes, national IDs)
- Which signer identity attributes are extracted from certificates (CPF/CNPJ, VAT number, etc.)

The simplest approach — a single hard-coded validation path for each supported regulation — would not scale. Adding a new country would require changes across the signing, validation, and inspection layers.

**Decision:**
A three-interface plug-in architecture where each country bundles all its regulation-specific logic into a single registration unit.

### 1. Core interfaces (all in `SimpleSign.Core.Extensions`)

**`ICountryExtension`** — the composite registration unit:
```csharp
public interface ICountryExtension
{
    string RegionCode { get; }
    string DisplayName { get; }
    IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders { get; }
    ISignatureManifestProvider? ManifestProvider { get; }
    IReadOnlyList<IChainValidationProvider> ChainValidationProviders { get; }
}
```

Three sub-interfaces:

- **`ITrustAnchorProvider`** — returns a list of root/intermediate CA certificates (bundled as embedded resources or loaded from a store).
- **`ISignatureManifestProvider`** — builds and parses structured metadata embedded as CMS signed attributes (each regulation defines its own OID and format).
- **`IChainValidationProvider`** — performs region-specific chain validation beyond standard X.509 path building: policy OID detection, assurance level mapping, national ID extraction, CRL/OCSP fallback rules. The `ValidateAsync` method is async for network-dependent validators.

`SignerContext` is the cross-cutting DTO passed to `BuildManifest`:
```csharp
public sealed class SignerContext
{
    public required string SignerName { get; init; }
    public string? SignerId { get; init; }        // CPF, SSN, NIF
    public string? Email { get; init; }
    public string? IpAddress { get; init; }
    public string? AuthenticationMethod { get; init; }
    public string? InstitutionName { get; init; }
    public string? InstitutionId { get; init; }    // CNPJ, VAT, EIN
    public string? LegalBasis { get; init; }       // "Lei 14.063", "eIDAS"
    public string? CommitmentType { get; init; }
}
```

### 2. BrasilExtension — reference implementation

`BrasilExtension` bundles 6 internal classes:

| Class | Interface | Responsibility |
|---|---|---|
| `IcpBrasilTrustAnchorProvider` | `ITrustAnchorProvider` | Loads 13 AC Raiz certificates (v4–v13) from assembly resources |
| `GovBrTrustAnchorProvider` | `ITrustAnchorProvider` | Loads Gov.br AC Raiz + Intermediaria + Final from resources |
| `IcpBrasilChainValidationProvider` | `IChainValidationProvider` | Detects ICP-Brasil policy OIDs (AD-RB → AD-RA), extracts CPF/CNPJ from SAN |
| `GovBrChainValidationProvider` | `IChainValidationProvider` | Detects Gov.br assurance levels (Bronze/Silver/Gold/Level), extracts CPF |
| `BrasilManifestProvider` | `ISignatureManifestProvider` | Builds/parses Lei 14.063 signature manifest JSON (OID `2.16.76.1.12.1.1`) |

### 3. Registration

**DI path:**
```csharp
services.AddSingleton<ICountryExtension, BrasilExtension>();
services.AddSingleton<ITrustAnchorProvider, IcpBrasilTrustAnchorProvider>();
services.AddSingleton<ITrustAnchorProvider, GovBrTrustAnchorProvider>();
```

**Non-DI path** (planned but not yet implemented):
```csharp
SimpleSigner.Document(pdf)
    .WithCountryExtension<BrasilExtension>()
    .WithCertificate(cert)
    .SignAsync();
```

### 4. Consumption in PAdES

| Layer | Extension point consumed | Mechanism |
|---|---|---|
| **Validation** | `ITrustAnchorProvider` | DI collection injected into `PdfSignatureValidator` constructor; roots loaded into `X509Chain.CustomTrustStore` |
| **Validation** | `IChainValidationProvider` | NOT consumed during built-in validation — region-specific validators are invoked separately by consumers (CLI, HostSigner, apps) |
| **Signing** | `ISignatureManifestProvider` | Extension methods (e.g. `WithAdvancedSignature`) map to `SignatureMetadata` → CMS signed attributes |
| **Inspection** | None (OID hard-coded) | `CmsParser` recognises manifest OID directly; no provider needed |

**Consequences:**
- Adding a new country requires implementing only 4 interfaces and registering the composite
- Trust anchors can be offline (embedded resources) or online (AIA chasing or downloaded lists)
- JSON manifests use AOT-safe source generators (no reflection)
- `IChainValidationProvider` is currently a standalone API — not yet wired into the built-in validation pipeline. Consumers call it independently (e.g., CLI commands, HostSigner validation service).
- `WithCountryExtension<T>()` on `SignerBuilder` is documented but not implemented. Currently, the only registration path is through DI (`AddSimpleSignBrasil()`).
- Three metadata types exist (`SignerContext`, `SignatureMetadata`, `AdvancedSignatureInfo`) with manual mapping — a potential simplification point.
- The manifest OID (`2.16.76.1.12.1.1`) is hard-coded in the CMS parser; manifest format is not extensible at runtime.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Single flat interface** (one big API per country) | Simple | No separation of concerns, hard to test | Rejected |
| **Three-interface composite (chosen)** | Clear separation, easy to test each concern, flexible | More files, consumer must know where to inject | **Chosen** |
| **No plug-in (hard-coded per country)** | Fast to implement first country | Impossible to extend, violates OCP | Rejected |
| **Attribute-based discovery** | Zero-config for new assemblies | Reflection, AOT incompatible | Rejected |

**Status:** Accepted. The three-interface composite is the canonical extension mechanism. `WithCountryExtension<T>()` on `SignerBuilder` is planned but not yet prioritised.
