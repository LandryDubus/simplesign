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

`SignerBuilder` holds configuration items as `private readonly` fields. Every `With*` method returns a **new instance** via a private copy constructor.

**Copy constructor pattern (simplified — actual fields may differ):**

```csharp
public sealed class SignerBuilder
{
    private readonly Stream _inputPdf;
    private readonly X509Certificate2? _certificate;
    private readonly string? _tsaUrl;
    // ... more private readonly fields

    public IReadOnlyList<ICountryExtension> CountryExtensions { get; }

    internal SignerBuilder(Stream inputPdf, ILogger? logger) { ... }

    // Private copy constructor — called by With(...)
    private SignerBuilder(
        Stream inputPdf, X509Certificate2? certificate,
        // ... all fields passed explicitly ...
        IReadOnlyList<ICountryExtension>? countryExtensions) { ... }

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

Methods are grouped by concern: certificate, timestamp, HTTP, signing algorithm, metadata, appearance, PAdES level (B-T, B-LT, B-LTA), PDF/A conformance, SubFilter selection, and advanced options (existing field targeting, operation IDs).

The only extension method in a separate assembly is `SignerBuilderBrasilExtensions.WithAdvancedSignature()` in `SimpleSign.Brasil`.

### 4. Terminal methods

Three overloads: stream-target (`SignAsync(stream, ct)` returns `Task`), byte-array (`SignAsync(ct)` returns `Task<byte[]>`), and detailed (`SignWithDetailsAsync(ct)` returns `Task<PdfSigningResult>` with metadata).

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

Before any PDF modification, `SignCoreAsync` validates: certificate presence/availability, certificate expiry, DocMDP lock, PDF/A compatibility (when enabled), and PAdES level sequencing.

**Consequences:**
- Thread-safe by construction: all builder state is `readonly`, shared across threads safely
- Immutable pattern prevents stale-read bugs: each `With*` starts from the previous state
- AOT compatible: callbacks use `Func<>` delegates, no dynamic invocation, no `Expression` trees
- Single obvious way to create a signer: `SimpleSigner.Document()` → `SignerBuilder` → terminal method
- Allocation overhead per `With*` call (full fields copy per operation) — negligible for typical usage
- Validation upfront prevents late failures after PDF modification
- `DeferredSigner` requires session state management; opaque blob approach avoids server-side storage but blobs can be large
- `BatchSigner` uses a mutable inner builder (`BatchSignerBuilder` returning `this`) — optimised for performance, not thread-safety

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Immutable fluent builder (chosen)** | Thread-safe, AOT-safe, self-documenting | Allocation overhead per step | **Chosen** |
| **Mutable builder** | Zero allocation, simpler implementation | Thread-unsafe, stale read bugs | Rejected |
| **Options object** | Familiar to .NET devs | No method-chaining discoverability | Rejected |
| **Decorator pattern** | Flexible runtime composition | Complex type hierarchy, hard to trace | Rejected |

**Status:** Accepted. The immutable fluent builder is the canonical API pattern. `SignerBuilder` will not become mutable. `DeferredSigner` and `DeferredSignerBuilder` extend the same pattern to two-phase signing.
