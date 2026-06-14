# ADR 0010: Fluent Builder API Pattern

**Status:** Accepted

**Context:**
PAdES signing requires configuring multiple independent concerns: the input document, signer certificate, timestamp authority, appearance, signature field options, LTV archival, metadata attributes, and output format. Traditional approaches include:

- **Constructor injection** — many optional parameters → telescoping constructors, confusing positional arguments
- **Options object** — passes a single mutable configuration object through the pipeline → callers can't tell which options are required vs. optional, and mutability allows stale reads
- **XML/JSON config files** — external configuration, compile-time type safety lost

The library's consumers include ASP.NET web APIs (DI, dependency injection), console CLIs, Windows tray apps (HostSigner), and cloud functions (AOT-compiled). The API must be intuitive, immutable, thread-safe, and AOT-compatible.

**Decision:**
An **immutable fluent builder** (`SignerBuilder`) accessed through a **static factory** (`SimpleSigner`).

### 1. Static factory entry point

`SimpleSigner` is a sealed class with a private constructor — it is never instantiated. It exposes three static overloads:

```csharp
var b1 = SimpleSigner.Document(pdfBytes);               // byte[]
var b2 = SimpleSigner.Document(stream);                  // seekable Stream
var b3 = await SimpleSigner.DocumentAsync(path);         // file path
```

All three return a `new SignerBuilder(...)` wrapping the PDF in a `MemoryStream`. This is the sole public entry point — no constructor access.

### 2. Immutable builder pattern

`SignerBuilder` holds 20 configuration items (19 private readonly fields + 1 public auto-property `CountryExtensions`). Every `With*` method returns a **new instance** via a private copy constructor.

**Copy constructor pattern:**

```csharp
public sealed class SignerBuilder
{
    private readonly Stream _inputPdf;
    private readonly X509Certificate2? _certificate;
    private readonly IReadOnlyList<X509Certificate2>? _chain;
    private readonly string? _tsaUrl;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly bool _hashAlgorithmExplicitlySet;
    private readonly SignatureFieldOptions _fieldOptions;
    private readonly HttpClient? _httpClient;
    private readonly HttpClient? _tsaHttpClient;
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly ILogger _logger;
    private readonly Func<byte[], Task<byte[]>>? _externalSigner;
    private readonly string? _signatureAlgorithmOid;
    private readonly bool _enableLtv;
    private readonly string? _archivalTsaUrl;
    private readonly string? _operationId;
    private readonly bool _enforcePdfA;
    private readonly SignatureMetadata? _metadata;
    private readonly bool _padesAttributes;
    public IReadOnlyList<ICountryExtension> CountryExtensions { get; }

    // Public constructor — called by SimpleSigner.Document()
    internal SignerBuilder(Stream inputPdf, ILogger? logger) { ... }

    // Private copy constructor — called by With(...)
    private SignerBuilder(
        Stream inputPdf, X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2>? chain, string? tsaUrl,
        HashAlgorithmName hashAlgorithm, bool hashAlgorithmExplicitlySet,
        SignatureFieldOptions fieldOptions, HttpClient? httpClient,
        HttpClient? tsaHttpClient, IHttpClientProvider? httpClientProvider,
        ILogger logger, Func<byte[], Task<byte[]>>? externalSigner,
        string? signatureAlgorithmOid, bool enableLtv, string? archivalTsaUrl,
        string? operationId, bool enforcePdfA, SignatureMetadata? metadata,
        bool padesAttributes, IReadOnlyList<ICountryExtension>? countryExtensions) { ... }

    // Private helper — creates new instance carrying forward unchanged fields
    private SignerBuilder With(
        X509Certificate2? certificate = null, ...) =>
        new(_inputPdf, ...);
}
```

Each `With*` method validates inputs, calls `With(...)` with only the changed parameters, and returns the new builder.

**Example chain (each step creates a new object):**
```csharp
var signed = SimpleSigner.Document(pdf)
    .WithCertificate(cert)
    .WithTimestamp("http://tsa.example")
    .WithAppearance(new SignatureAppearance { AutoPosition = true })
    .WithLtv()
    .SignAsync();
```

### 3. Configuration methods (all on `SignerBuilder`, not extensions)

| Category | Methods |
|---|---|
| **Certificate** | `WithCertificate(cert)`, `WithCertificate(cert, chain)` |
| **Timestamp** | `WithTimestamp(url)`, `WithTimestamp(url, httpClient)` |
| **HTTP** | `WithHttpClient(client)`, `WithHttpClientProvider(provider)` |
| **Signing** | `WithHashAlgorithm(name)`, `WithSignatureAlgorithm(oid)`, `WithExternalSigner(fn)` |
| **Metadata** | `WithSignerName(name)`, `WithFieldName(name)`, `WithMetadata(metadata)` |
| **Appearance** | `WithAppearance(appearance)`, `AsCertification(level)` |
| **PAdES level** | `WithLtv()`, `WithArchivalTimestamp(url)` |
| **PDF/A** | `WithPdfAPreservation()` |
| **SubFilter** | `WithSubFilter(filter)`, `WithLegacyCms()` |
| **Advanced** | `WithExistingField(name)`, `WithOperationId(id)` |

The only extension method in a separate assembly is `SignerBuilderBrasilExtensions.WithAdvancedSignature()` in `SimpleSign.Brasil`.

### 4. Terminal methods

| Method | Returns |
|---|---|
| `SignAsync(stream, ct)` | `Task` — writes signed PDF to stream |
| `SignAsync(ct)` | `Task<byte[]>` — returns signed PDF bytes |
| `SignWithDetailsAsync(ct)` | `Task<PdfSigningResult>` — bytes + warnings + DSS flag |

### 5. Local vs. external signing

**Local:** certificate has private key → `CmsSignatureBuilder.Build()` signs the CMS SignedData directly using the BCL key.

**External:** delegate-based callback → `CmsSignatureBuilder.BuildAsync()` calls the delegate with the hash to sign, then embeds the produced CMS.

```csharp
.WithExternalSigner(cert, async (hash, hashAlg) =>
{
    return await hsm.SignAsync(hash, hashAlg);
})
```

### 6. Two-phase deferred signing (`DeferredSigner`)

For web/mobile scenarios where the private key is on a different machine:

```csharp
// Phase 1 — server
var prepared = await DeferredSigner.PrepareAsync(pdf, cert);
sessionDb.Save(prepared.SessionData);
return prepared.HashToSign;  // send to client

// Phase 2 — client signs (browser, mobile)
byte[] rawSig = await webSigner.SignAsync(prepared.HashToSign);

// Phase 2b — server completes
var signedPdf = await DeferredSigner.CompleteAsync(sessionData, rawSig);
```

`DeferredSigningSession` serialises to JSON with optional HMAC integrity check. AOT-safe via `JsonSerializerContext`.

### 7. Validation upfront

Before any PDF modification, `SignCoreAsync` validates:

| Check | Error |
|---|---|
| Certificate present and has private key (or external signer set) | `InvalidOperationException` |
| Certificate not expired | `ArgumentException` |
| DocMDP lock (prior certification forbids modification) | `InvalidOperationException` |
| PDF/A preservation enabled → `PdfAPreservationValidator` checks pass | `SigningException` |
| PAdES level sequence respected (timestamp before LTV before archival) | `InvalidOperationException` |

**Consequences:**
- Thread-safe by construction: all builder state is `readonly`, shared across threads safely
- Immutable pattern prevents stale-read bugs: each `With*` starts from the previous state
- AOT compatible: callbacks use `Func<>` delegates, no dynamic invocation, no `Expression` trees
- Single obvious way to create a signer: `SimpleSigner.Document()` → `SignerBuilder` → terminal method
- Allocation overhead per `With*` call (20-item copy per operation) — negligible for typical usage (<10 calls)
- Validation upfront prevents late failures after PDF modification
- `DeferredSigner` requires session state management; opaque blob approach avoids server-side storage but blobs can be large (~100 KB)
- `BatchSigner` uses a mutable inner builder (`BatchSignerBuilder` returning `this`) — optimised for performance, not thread-safety

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Immutable fluent builder (chosen)** | Thread-safe, AOT-safe, self-documenting | Allocation overhead per step | **Chosen** |
| **Mutable builder** | Zero allocation, simpler implementation | Thread-unsafe, stale read bugs | Rejected |
| **Options object** | Familiar to .NET devs | No method-chaining discoverability | Rejected |
| **Decorator pattern** | Flexible runtime composition | Complex type hierarchy, hard to trace | Rejected |

**Status:** Accepted. The immutable fluent builder is the canonical API pattern. `SignerBuilder` will not become mutable. `DeferredSigner` and `DeferredSignerBuilder` extend the same pattern to two-phase signing.
