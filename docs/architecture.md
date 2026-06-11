← [Back to README](../README.md)

# Architecture & Design

## Architecture

```
SimpleSign.Core               Crypto primitives, CMS, TSA, revocation, HTTP
├── Crypto/                    CmsSignatureBuilder, TimestampClient, TsaPool, CmsParser
├── Validation/                CryptoVerifier, CertificateChainUtility, RevocationChecker
├── Revocation/                CrlClient, OcspClient, RevocationChecker
└── Http/                      IHttpClientProvider

SimpleSign.Pdf                 PDF structure parsing (no crypto)
├── PdfStructureReader         Xref, objects, signature fields
└── PdfStructureParser         Low-level token/stream parser

SimpleSign.PAdES               PDF Advanced Electronic Signatures
├── SimpleSigner               Fluent API entry point
├── SignerBuilder               Immutable builder (16 options)
├── PdfSignatureWriter         Incremental PDF update (append-only)
├── BatchSigner                Parallel signing with metrics
├── DeferredSigner             Two-phase signing for web apps
├── LtvEmbedder                DSS dictionary (CRL/OCSP/VRI)
├── DocTimeStampWriter         PAdES B-LTA archival timestamp
├── Validation/                PdfSignatureValidator, IntegrityVerifier, DssExtractor
├── Inspection/                PdfSignatureInspector (static)
└── PadesExtractor             CMS extraction from signed PDFs

SimpleSign.Brasil              Brazilian PKI (ICP-Brasil + Gov.br + Lei 14.063)
├── IcpBrasilChainValidator    ICP-Brasil chain validation (AD-RB..AD-RA)
├── GovBrChainValidator        Gov.br assurance levels
├── AdvancedSignatureInfo      AEA Lei 14.063 metadata
└── BrasilExtension            Registration entry point

SimpleSign.Cli                 CLI tool (Spectre.Console)
SimpleSign.HostSigner          Windows tray app — local signing HTTP API
```

## Design Principles

| Principle | Implementation |
|---|---|
| **Immutable builders** | Every `.WithX()` returns a new instance — safe to share across threads |
| **Async-first** | All signing/validation methods return `Task<T>` — no blocking calls anywhere |
| **Zero-allocation hot paths** | `Span<byte>` and `ReadOnlySpan<byte>` for PDF parsing and hash computation |
| **Pooled memory** | `RecyclableMemoryStream` for buffer reuse |
| **Structured logging** | 105 `[LoggerMessage]` definitions — zero-cost when disabled |
| **Native AOT** | No reflection in hot paths, trimmer-friendly |
| **Nullable enabled** | All public APIs are fully annotated |

## Quality

| Metric | Value |
|---|---|
| **Tests** | 1,700+ (unit, integration, interop, fuzz, corpus, ISO compliance) |
| **Test categories** | Unit (algorithm + ISO 32000 compliance), Integration (sign→validate round-trip), Interop (~150 scenarios, 18 files: EU DSS, iText, PDFBox, pyHanko, OpenSSL, xmlsec1, veraPDF), ETSI Corpus (multi-revision + 6 country fixtures), Fuzz (7 SharpFuzz harnesses), CLI (command-line tests), VeraPDF (PDF/A conformance), Stress (1,000-op memory + concurrency), Mutation (Stryker Advanced level) |
| **Real-world fixtures** | 57 PDFs from Adobe, iText, EU DSS, ICP-Brasil, Belgian eID, Spanish/German/French/Hungarian gov |
| **Source lines** | ~32,800 |
| **Warnings** | 0 (all warnings treated as errors) |
| **Code analysis** | Full Roslyn analyzer suite enabled |
| **CI** | Build + test (3 OS), CodeQL SAST, fuzz (weekly), mutation testing, stress tests, coverage report, AOT smoke test |
| **AOT** | Native AOT smoke-tested in CI |
| **Target frameworks** | net8.0 + net10.0 |
| **Algorithms** | RSA PKCS#1 v1.5, RSA-PSS (PS256/PS384/PS512), ECDSA (P-256/P-384/P-521), EdDSA (Ed25519/Ed448, verify), SHA-256/384/512, SHA3-256/384/512 (NET 9+) |
| **PDF/A levels** | 1a/1b, 2a/2b/2u, 3a/3b/3u, 4a/4b/4u/4e (ISO 19005-1/2/3/4) |
| **ICP-Brasil profiles** | AD-RB, AD-RT, AD-RV, AD-RC, AD-RA (CAdES-XL via CmsAttribute injection) |
| **Documentation** | 4 ADRs, 2 migration guides, 3 issue templates |

## Resilience

| Scenario | Behavior |
|---|---|
| Malformed xref table | Falls back to brute-force `/ByteRange` scanning |
| BER-encoded CMS (Gov.br) | Parses both BER and DER transparently |
| Missing `/Length` in streams | Scans up to 10 MB for `endstream` marker |
| Encrypted PDF | Throws `EncryptedPdfException` with actionable message |
| Malformed CMS structure | Returns partial field info, no crash |
| SHA-1 legacy signatures | Validates (deprecated since 2016, supported for legacy) |
