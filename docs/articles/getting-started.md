# Getting Started

## Installation

SimpleSign packages are split by concern — install only what you need:

```bash
# Full PAdES stack (most common)
dotnet add package SimpleSign

# Or individual packages
dotnet add package SimpleSign.PAdES    # PAdES signing, validation, inspection
dotnet add package SimpleSign.Brasil   # ICP-Brasil trust anchors
dotnet add package SimpleSign.HtmlToPdf # HTML-to-PDF conversion
```

### Package Dependency Graph

```
SimpleSign (meta-package)
├── SimpleSign.PAdES        PDF signing & validation (PAdES B-B/T/LT/LTA)
│   ├── SimpleSign.Pdf      PDF structure parser (xref, objects, fields)
│   └── SimpleSign.Core     Crypto primitives, CMS, TSA, revocation
│
SimpleSign.Brasil           ICP-Brasil + Gov.br + Lei 14.063  → depends on PAdES
SimpleSign.HtmlToPdf        Pure-.NET HTML→PDF (independent)
```

## Sign a PDF

The simplest way to sign a PDF:

```csharp
using SimpleSign.PAdES;

// From a byte array
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .SignAsync();

File.WriteAllBytes("contract-signed.pdf", signedPdf);

// Or from a file path (async I/O)
var builder = await SimpleSigner.DocumentAsync("contract.pdf");
var signedPdf2 = await builder
    .WithCertificate(certificate)
    .SignAsync();
```

This creates a **PAdES B-B** (basic) signature.

## Add a Timestamp (PAdES B-T)

Include an RFC 3161 timestamp from a trusted TSA:

```csharp
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithTimestamp("http://timestamp.digicert.com")
    .SignAsync();
```

## Long-Term Validation (PAdES B-LT / B-LTA)

Embed CRL/OCSP responses so the signature can be validated even after the certificate expires:

```csharp
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithTimestamp("http://timestamp.digicert.com")
    .WithLtv()                    // Embed revocation data (B-LT)
    .WithArchivalTimestamp()      // Add archive timestamp (B-LTA)
    .SignAsync();
```

## Signature Appearance

Add a visible signature with optional QR code:

```csharp
var appearance = new SignatureAppearance
{
    Page = 1,
    X = 50, Y = 50,
    ShowDate = true,
    ShowReason = true,
    BackgroundImagePng = logoBytes,
    VerificationUrl = "https://verify.example.com/abc123"
};

await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithAppearance(appearance)
    .SignAsync(output);
```

## Validate Signatures

```csharp
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

var validator = new PdfSignatureValidator(new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true
});

var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));

foreach (var r in results)
{
    Console.WriteLine($"{r.FieldName}: Valid={r.IsValid}");
    Console.WriteLine($"  Integrity={r.IsIntegrityValid}");
    Console.WriteLine($"  Chain={r.IsCertificateChainValid}");
}
```

## Certificate Chain

Pass the full intermediate chain explicitly when AIA is unavailable or you want to guarantee
the chain is embedded without network fetches at signing time:

```csharp
var signed = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert, [intermediateCert, rootCert])
    .WithLtv()
    .SignAsync();
```

## Signature Algorithm Override

Force RSASSA-PSS on a plain `rsaEncryption` certificate:

```csharp
using SimpleSign.Core;

var signed = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithSignatureAlgorithm(Oids.RsaPss)
    .WithTimestamp("http://timestamp.digicert.com")
    .SignAsync();
```

Compatibility is validated at signing time — an `ArgumentException` is thrown for incompatible
combinations (e.g. PSS on an ECDSA key).

## HTTP Client Management

By default, SimpleSign creates its own `HttpClient`. In ASP.NET Core use the named-client
pattern to let `IHttpClientFactory` manage the lifetime:

```csharp
// In Program.cs / Startup.cs:
services.AddHttpClient("SimpleSign", client =>
{
    client.Timeout = TimeSpan.FromSeconds(15);
});
services.AddSimpleSign(opts => opts.HttpClientName = "SimpleSign");
// AddSimpleSign auto-detects IHttpClientFactory in the container.
```

For independent per-operation clients (e.g. bearer token on TSA only):

```csharp
services.AddHttpClient("SimpleSign.Tsa", client =>
    client.DefaultRequestHeaders.Authorization =
        new AuthenticationHeaderValue("Bearer", myToken));
services.AddHttpClient("SimpleSign.Revocation");

var tsaClient        = httpClientFactory.CreateClient("SimpleSign.Tsa");
var revocationClient = httpClientFactory.CreateClient("SimpleSign.Revocation");

var signed = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithTimestamp(tsaUrl, tsaClient)     // TSA calls only
    .WithLtv()
    .WithHttpClient(revocationClient)     // OCSP/CRL + TSA fallback
    .SignAsync();
```

For a typed `PdfSignatureValidator` client:

```csharp
services.AddHttpClient<PdfSignatureValidator>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(10);
});
// Resolves PdfSignatureValidator with the managed HttpClient injected automatically.
```

If you have a custom `IHttpClientProvider`, use `WithHttpClientProvider` — the provider is
called lazily at signing time, not at builder-construction time:

```csharp
var signed = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithTimestamp(tsaUrl)
    .WithHttpClientProvider(myProvider)
    .SignAsync();
```

## Dependency Injection

Register SimpleSign in your DI container:

```csharp
using SimpleSign.PAdES;

services.AddSimpleSign(options =>
{
    options.TsaUrl = "http://timestamp.digicert.com";
});

// For ICP-Brasil support
services.AddSimpleSignBrasil();
```

## Next Steps

- [Deferred Signing](deferred-signing.md) — for web apps where the key is on a client device
- [Inspection & Validation](inspection-validation.md) — detailed metadata extraction
- [ICP-Brasil](icp-brasil.md) — Brazilian PKI integration
