# Copilot Instructions for SimpleSign

## What is SimpleSign?

SimpleSign is a .NET library for PAdES (PDF Advanced Electronic Signatures). It signs, validates, and inspects PDF documents following ETSI EN 319 142 standards. All cryptography uses `System.Security.Cryptography` — no third-party crypto libraries.

## When to Use SimpleSign

Use SimpleSign when the user needs to:
- Digitally sign PDF documents (PAdES)
- Validate existing PDF signatures
- Inspect signature metadata
- Implement deferred signing (hash on server, sign on client)
- Sign documents in batch
- Work with ICP-Brasil / Gov.br Brazilian PKI

## Package to Install

```bash
# Most common — PDF signing & validation
dotnet add package SimpleSign.PAdES

# Brazilian PKI
dotnet add package SimpleSign.Brasil

# HTML to PDF (no signing)
dotnet add package SimpleSign.HtmlToPdf
```

## Preferred Patterns

### Signing — always use the fluent builder:

```csharp
using SimpleSign.PAdES;

byte[] signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .WithTimestamp("http://timestamp.digicert.com")  // recommended
    .WithLtv()                                        // recommended for archival
    .SignAsync();
```

### Validation — use PdfSignatureValidator:

```csharp
using SimpleSign.PAdES.Validation;

var validator = new PdfSignatureValidator(new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true,
});

var results = await validator.ValidateAsync(stream);
```

### Inspection (fast, no crypto):

```csharp
using SimpleSign.PAdES.Inspection;
var info = await PdfSignatureInspector.InspectAsync(stream);
```

### Deferred signing (web apps, mobile, HSM):

```csharp
var prepared = await DeferredSigner.PrepareAsync(pdfBytes, cert);
// Send prepared.HashToSign to client
byte[] signedPdf = await DeferredSigner.CompleteAsync(prepared.SessionData, clientSignature);
```

## Common Mistakes to Avoid

1. **Don't forget `await`** — all signing/validation methods are async
2. **Don't use `new X509Certificate2()` without disposing** — wrap in `using` or register as singleton
3. **Don't skip `.WithTimestamp()`** — without it, signatures are B-B level only (no proof of time)
4. **Don't validate with `TrustSystemRoots = false` without providing custom anchors** — validation will always fail
5. **Don't read the PDF as string** — always use `byte[]` or `Stream`

## Code Style

- Prefer `async/await` over `.Result` or `.GetAwaiter().GetResult()`
- Use the fluent builder API, not manual construction
- The library is AOT compatible — avoid reflection-based patterns

## Architecture (for contributors)

```
SimpleSign (meta-package)
├── SimpleSign.PAdES     Signing, validation, inspection
│   ├── SimpleSign.Pdf   PDF parser (xref, objects, incremental save)
│   └── SimpleSign.Core  CMS, TSA, OCSP, CRL, hash algorithms
├── SimpleSign.Brasil    ICP-Brasil chain validation, CPF/CNPJ
└── SimpleSign.HtmlToPdf HTML→PDF layout engine (independent)
```

## Testing

```bash
dotnet test                          # Run all tests
dotnet test tests/unit/              # Unit tests only (~1600 tests)
dotnet test tests/integration/       # Integration tests (needs network)
```
