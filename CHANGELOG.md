# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-05-20

### Fixed

- **CAdES signingTime** — `signingTime` signed attribute is no longer included; the attribute is not allowed by ETSI EN 319 122 and was causing conformance errors (CheckAllowedAttributes violation)
- **Null guard in ValidateChainStep** — `PdfSignatureValidator.ValidateChainStep` no longer throws `NullReferenceException` when the signer certificate is absent; returns a clean validation error instead
- **Async AIA chain fetching** — `PdfSignatureValidator.ValidateChainStep` is now async and pre-fetches AIA certificates before `X509Chain.Build()`, fixing silent chain failures on macOS/Linux where auto-fetch is unreliable
- **BFS AIA chasing** — `CertificateChainUtility` now performs breadth-first multi-tier AIA chasing, enabling full ICP-Brasil intermediate chain resolution
- **P7B certificate bags** — `CertificateLoader` and `CertificateChainUtility.LoadCertsFromBytes` now handle PKCS#7 certificate bags (`.p7b`)
- **ICP-Brasil trust anchors** — `HostSigner` and `ValidationService` now inject `BrasilExtension` trust anchor providers so ICP-Brasil chains validate correctly

## [0.2.1] - 2026-05-19

### Fixed

- **OCSP `certs[0]` SEQUENCE OF wrapper** — correctly unwrap the inner `SEQUENCE OF Certificate` inside the OCSP BasicOCSPResponse `certs [0] EXPLICIT` wrapper (was failing to load OCSP responder certs)
- **CRL v2 bare version INTEGER** — handle the bare `INTEGER` version field in TBSCertList (v2 CRLs use `02 01 01` directly, not wrapped in a context tag like X.509 certs)
- **CMS serial comparison** — use `ReadIntegerBytes` for serial number comparison to preserve DER leading zeros (e.g. serial `00BB3F...` was being truncated by `BigInteger.ToString("X")`)
- **BER tolerance in extension parsers** — `CrlClient.GetCrlUrl`, `OcspClient.ParseAiaUri`, and `CertificateChainUtility.ExtractAiaUrls` now use `AsnEncodingRules.BER` (extensions can be BER-encoded; DER was silently losing revocation URLs)
- **Issuer cert lookup** — compare by `SubjectName.RawData` bytes first in OCSP and revocation checker (string comparison failed for re-encoded DNs with different ASN.1 string types)
- **TimestampClient BER tolerance** — `ExtractSignatureValue` and `ParseTimeStampResponse` now use BER instead of DER (tolerates Brazilian CAs and TSA servers with BER-encoded responses)
- **TSA signer cert identification** — `TimestampValidator` now identifies the correct signer certificate via `issuerAndSerialNumber` instead of blindly using `Certificates[0]` (fixes multi-cert TSA tokens like PostSignum)
- **DSS endstream detection** — `DssExtractor` now handles both `\r\n` and `\n` before the `endstream` keyword (PDF spec allows both; was silently losing embedded CRLs)
- **CRL issuer DN matching** — tolerate UTF8String vs PrintableString encoding differences when matching CRL issuer to certificate issuer
- **signingCertificate hash algorithm** — correctly use SHA-1 for V1 (`signingCertificate`) and SHA-256 for V2 (`signingCertificateV2`) attributes
- **Inspector CMS parse failure** — `PdfSignatureInspector` now logs a warning when CMS parsing fails (was silently returning minimal info)
- **CI formatting (IDE0055)** — enforce LF line endings via `.gitattributes` to prevent spurious formatting errors on Windows CI runners

### Added

- **Diagnostic logging** — 13 new structured log messages across revocation, OCSP, CMS parser, timestamp validator, inspector, and LTV embedder for improved troubleshooting in verbose mode
- **CmsParser normalized issuer fallback** — 3-step signer cert lookup: exact bytes → normalized issuer → issuer-only (resilient to DN encoding differences)

### Changed

- **CLI renamed** — tool command changed from `simplesign-cli` to `simplesign`

## [0.2.0] - 2026-05-17

### Added

- **Benchmark suite** — 6 benchmark classes (46+ benchmarks): feature overhead, incremental signing, stream I/O, deferred signing latency, PDF parsing cost, batch concurrency. Results in `BenchmarkDotNet.Artifacts/`
- **Fuzz testing** — 7 SharpFuzz targets: `dss`, `timestamp`, `ocsp`, `pdf`, `cms`, `validator`, `xref`. Added 5-second timeout cancellation and unified `IsExpectedException()` filter. Corpus seeds: PAdES-B-B, PAdES-LTA, bad-encoded-cms
- **Stress tests** — 3 tests tagged `[Trait("Category","Stress")]`: 1,000 sequential signs (memory growth < 50 MB), 500 concurrent (SemaphoreSlim, < 60 s), 100 incremental signatures on one document
- **Docs split** — `docs/interoperability.md`, `docs/conformance.md`, `docs/performance.md`, `docs/architecture.md` (extracted from README)
- **ISO 32000-1:2008 compliance test suite** — 46 unit tests mapping to specific standard sections (§7.3.4.2, §7.5.4–8, §7.9.4, §8.6.5, §8.7, §12.7, §12.8.1–3)
- **ISO 32000-2:2020 (PDF 2.0) compliance** — PDF 2.0 header detection, VRI validation, SHA-1 deprecation flags
- **ETSI EN 319 142 compliance tests** — 16 tests covering B-B/B-T/B-LT/B-LTA profiles, signed attributes, conformance detection
- **RFC 5652 (CMS) compliance tests** — 15 tests for SignedData structure, SignerInfo, signed attributes, DER encoding
- **DOC-ICP-15 compliance tests** — 16 tests for AD-RB/AD-RT profiles, ICP-Brasil chain, CPF/CNPJ extraction, Lei 14.063
- **OWASP security hardening** — SSRF protection (UrlValidator), path traversal guards, CORS restriction, nonce hardening, error sanitization, HMAC session integrity, SHA-1/MD5 rejection
- **CLI install script** from GitHub Releases (`scripts/install-cli.ps1`)
- **Real-world compatibility matrix** — Adobe, iText, pyHanko, LibreOffice, Word, EU DSS, ICP-Brasil
- **Resilience features** — BER/DER handling, malformed xref recovery, encrypted PDF detection

### Fixed

- **Cross-reference streams** — incremental updates now use xref streams when the original PDF uses them (ISO 32000 §7.5.8), with self-entry included
- **ObjStm-compressed AcroForm** — preserve all `/Fields` entries from compressed Object Streams when signing multi-signature PDFs
- **Indirect `/Fields` references** — resolve indirect references in AcroForm during signing
- **`/Type /AcroForm` removed** — adding this key broke Adobe Reader diff analysis on multi-signed PDFs
- **Duplicate field names** — ObjStm-compressed PDFs no longer produce duplicate `/Fields` entries
- **`/P` page reference** — added to field annotations for both regular and ObjStm-compressed page objects
- **`/Annots` array** — page annotation updates now work for ObjStm-compressed pages
- **`/M` date format** — changed from `Z` suffix to `+00'00'` per ISO 32000 §7.9.4
- **DocTimeStampWriter** — skip unnecessary Catalog rewrite when `reuseAcroForm=true`
- **AcroForm key preservation** — `/DR`, `/DA`, `/Q`, `/NeedAppearances`, `/XFA` no longer lost during signing
- **`EscapePdfString`** — added `\n`, `\r`, `\t`, `\b`, `\f` escapes per ISO 32000 §7.3.4.2
- **`endobj` termination** — catalog and page objects now always end with newline separator
- **Code review fixes** — 29 issues (2 Critical, 13 High, 14 Medium): `IsValid` includes revocation check, revocation exception handling, `IsNotRevoked` default, nonce entropy, error sanitization, and more

### Changed

- **Test assertions** — migrated from FluentAssertions (Xceed commercial license) to Shouldly (MIT) across all 7 test projects
- **HostSigner** — React/shadcn UI overhaul
- **README** — comprehensive rewrite: lib-focused structure, real benchmark numbers, dependency clarity, merged enterprise features

[0.2.2]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.2
[0.2.1]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.1
[0.2.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.0
