# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.3] - 2026-06-09

### Added

- **`SignerBuilder.WithSignatureAlgorithm(oid)`** — new public API to force a specific signature algorithm OID on the local signing path. Primary use case: producing RSASSA-PSS signatures with certificates whose public key OID is `rsaEncryption` (`1.2.840.113549.1.1.1`). Compatibility with the certificate's key type is validated at signing time.
- **`CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility`** — shared validator that throws `ArgumentException` when the requested signature OID is incompatible with the certificate's public key family (e.g., ECDSA OID on an RSA cert).
- **`DeferredSigningOptions.HashAlgorithmExplicitlySet`** — new `bool` property that distinguishes "user chose SHA-256" from "library defaulted to SHA-256", enabling algorithm inference on the deferred signing path.
- **`AlgorithmInference.ExtractPssParamsFromSpki`** — reads PSS parameters from SubjectPublicKeyInfo when the public key OID is `id-RSASSA-PSS` (RFC 4055 §4), enabling PSS detection on certificates that encode the constraint at the SPKI level rather than the signature algorithm level.
- **`TestCertificateFactory.CreatePssSelfSignedCert`** — new test helper that creates PSS-issued self-signed certificates with embedded `RSASSA-PSS-params`.
- **`TestCertificateFactory.TryCreateEdDsaCert`** — new test helper that creates Ed25519 self-signed certificates on .NET 9+; returns `null` on unsupported platforms. Enables end-to-end EdDSA signing and compatibility validation tests.

### Fixed

- **PSS cert's `RSASSA-PSS-params` ignored at the SPKI level** — certificates that encode the PSS constraint at the SubjectPublicKeyInfo level (`PublicKey.Oid.Value == Oids.RsaPss`, RFC 4055 §4) were not detected as PSS certs, causing `DetectRsaPadding` to return PKCS#1 and `DetectSignatureAlgorithmOid` to produce `rsaEncryption` instead of `id-RSASSA-PSS`. The new `AlgorithmInference.ExtractPssParamsFromSpki` reads the SPKI parameters field, and all four PSS detection points (`AlgorithmInference`, `SignerBuilder.DetectSignatureAlgorithmOid`, `DeferredSigner.DetectSignatureAlgorithmOid`, `CmsSignatureBuilder.GetSignatureAlgorithmOid`) now check both `PublicKey.Oid.Value` and `SignatureAlgorithm.Value`.
- **PSS cert's `RSASSA-PSS-params` ignored when inferring hash** — certificates issued with `id-RSASSA-PSS` and declaring SHA-384 or SHA-512 in their PSS params were always signed with SHA-256 unless the caller explicitly called `.WithHashAlgorithm()`. The new `AlgorithmInference.ResolveEffectiveHashAlgorithm` helper reads the hash from the cert's DER-encoded PSS params (via `CryptoUtility.ParsePssHashAlgorithm`) and uses it when the user has not overridden the default. Applied to `SignerBuilder`, `DeferredSigner`, and `DeferredSignerBuilder`.
- **Default hash for RSA PKCS#1 always SHA-256 regardless of key size** — RSA keys >= 3072 bits now default to SHA-384 per NIST SP 800-57 Part 1 Rev. 5, Table 2. Smaller keys remain at SHA-256. Applied to all three signing paths.
- **`DeferredSigner.CompleteAsync` timestamp hash used wrong algorithm** — when the deferred signer chose PKCS#1 SHA-512, the timestamp request was still sent with SHA-256. `CompleteAsync` now derives the timestamp hash from the CMS digest OID via `HashAlgorithmFromDigestOid`, which correctly handles SHA-384 and SHA-512.
- **`WithExternalSigner` bypassed algorithm inference** — both overloads of `SignerBuilder.WithExternalSigner` (with and without chain) now resolve the effective hash via `AlgorithmInference` before calling `DetectSignatureAlgorithmOid`, ensuring PSS params and key-size defaults are honoured on the external-signer path.
- **`SelectHashForRsaKeySize` too-broad catch** — narrowed to `CryptographicException` so `NotSupportedException` from other sources propagates correctly.
- **`CmsSignatureBuilder.BuildSignedData` mis-logged PSS detection** — the debug log now checks `signatureOid == Oids.RsaPss` instead of comparing the original OID to `Oids.RsaPss`.
- **`ExtractCmsFromPdf` hex stripping off by one** — the `/Contents` hex string trimmer was stripping individual `'0'` characters instead of `"00"` byte pairs, corrupting hex values containing embedded `0` digits.
- **No compatibility validation on signature algorithm OID** — previously, setting an incompatible OID (e.g., ECDSA OID on an RSA cert) produced a structurally invalid CMS with no error at signing time. Now validated at `CmsSignatureBuilder.Build`, `BuildAsync`, and `DeferredSigner.PrepareAsync`.
- **`_signatureAlgorithmOid` ignored on local signing path** — `SignerBuilder.SignCoreAsync` only passed the OID to the external-signer branch. Now threaded through both branches via the new `signatureAlgorithmOid` parameter on `CmsSignatureBuilder.Build`.
- **PDF/A-3b `spacingCompliesPDFA` on signed PDFs** — residual ISO 19005-3 §6.1.9 Test 1 failures on objects 99, 75, and 114 (the three objects appended by the LTV + DocTimeStamp signing chain) when the source PDF is bare-`%%EOF` (no EOL after `%%EOF`). The new `IncrementalUpdateUtility.EnsureTrailingEol` helper is called by all three writers (`PdfSignatureWriter`, `LtvEmbedder`, `DocTimeStampWriter`) after they copy the source PDF into the result stream, guaranteeing the first new object written is preceded by an EOL marker.
- **LTV catalog write missing trailing EOL** — `LtvEmbedder.BuildUpdatedCatalogDss` now also normalises CRLF→LF and falls back to a depth-aware `PdfStructureParser.FindOutermostDictClose` when the `>>\nendobj` sentinel is not found, and appends a `\n` to the rewritten catalog if it does not end with an EOL marker. This is the root cause of the 3 object-level failures (the xref stream written immediately after the catalog rewrite would otherwise be the first object not preceded by an EOL).
- **LTV early-return path with bare-`%%EOF` source** — when no CRL/OCSP data can be collected, the embedder now still passes the source through `EnsureTrailingEol` so a follow-up incremental update is always LF-preceded. The 4 corresponding tests were updated to assert the new trailing-EOL behavior.

### Improved

- **Test coverage for algorithm inference** — 26 new tests across 4 new test files:
  - `AlgorithmInferenceTests.cs` (10 tests) — PSS params extraction, key-size hash, default hash, SPKI-level PSS detection on `SimpleSigner`.
  - `DeferredAlgorithmInferenceTests.cs` (6 tests) — PSS params, key-size hash, default hash, end-to-end PSS deferred signing.
  - `DeferredSignerBuilderAlgorithmInferenceTests.cs` (3 tests) — PSS params, key-size hash, explicit hash passthrough.
  - `CmsSignatureBuilderCompatibilityTests.cs` (7 tests) — RSA, ECDSA, EdDSA compatible/incompatible OID pairs; PSS OID build.
- **EdDSA support** — `TestCertificateFactory.TryCreateEdDsaCert` on .NET 9+ with `#if`-wrapped platform guards. EdDSA compatibility tests auto-skip on unsupported platforms.
- **New test helpers** — `TestCertificateFactory.CreatePssSelfSignedCert` for PSS-issued certs with arbitrary hash.

## [0.3.2] - 2026-06-08

### Added

- **RFC 4055 §3.1 RSASSA-PSS-params** — `CmsSignatureBuilder` now emits the full `RSASSA-PSS-params` structure (hashAlgorithm + maskGenAlgorithm with id-mgf1 + same hash + saltLength) when signing with `id-RSASSA-PSS`, instead of leaving the parameters field empty. Required for acceptance by Adobe Acrobat, EU DSS, iText, and eIDAS validators (PS256 / PS384 / PS512).
- **`Oids.Mgf1`** — new `1.2.840.113549.1.1.8` constant for the id-mgf1 mask-generation function used inside the PSS params.
- **`CryptoUtility.ParsePssHashAlgorithm`** — parses the hash OID from a DER-encoded `RSASSA-PSS-params` structure (RFC 4055 §3.1); returns SHA-256 as the RFC default when the params are absent or the hash OID is unrecognised.
- **External signer chain overloads** — two new `SignerBuilder.WithExternalSigner(..., chain)` overloads (one with explicit OID, one with auto-detection) let HSM / cloud-KMS callers supply the pre-fetched intermediate certificate chain, avoiding redundant AIA HTTP requests during LTV embedding.
- **PSS-params-aware revocation verification** — `OcspClient.VerifyOcspSignature`, `CrlClient.VerifyCrlSignature`, and `TimestampValidator.VerifyTsaSignature` now accept and honour the `RSASSA-PSS-params` from the response / token; PS384 and PS512 responses are no longer silently verified with SHA-256.
- **PDF/A-2/3 conformance tests** — new `PdfAConformanceTests` covering the `/F 132` Print flag, `LF` after `obj` in incremental updates, CRLF-aware `AppendAnnots` / `InsertIntoDict`, and end-to-end signing of a PDF/A-3b-labelled document.
- **PS256/PS384/PS512 test coverage** — round-trip signing and validation for all three PSS hash variants, plus parser/params assertions in `Phase3ProductionTests`.

### Fixed

- **PDF/A-2/3 conformance after signing** — `BuildFieldAnnotation` previously emitted `/F 0` for invisible signature widgets, failing ISO 19005-3 §6.3.2 Test 2 (the Print flag must be set even when the widget is invisible). The widget now always carries `/F 132` (Print + Locked). `DocTimeStampWriter` had the same bug; also fixed.
- **Indirect-object EOL after `obj`** — `BuildUpdatedPageObject` previously wrote `"N 0 obj <<"` with a single space, failing ISO 19005-3 §6.1.9 Test 1 (`spacingCompliesPDFA`). Now writes `"N 0 obj\n<<"`.
- **CRLF source PDF corruption** — `AppendAnnots` and `InsertIntoDict` used `LastIndexOf(">>\nendobj")` which never matched on Windows / iText / Adobe source PDFs (CRLF line endings), falling back to a depth-blind `LastIndexOf(">>")` that could insert new keys inside a nested dictionary. Both now normalise CRLF → LF and fall back to a depth-aware `FindOutermostDictClose` that finds the closing `>>` of the top-level dictionary.
- **PS384/PS512 OCSP, CRL, and TSA verification** — previously all PSS signatures were verified with SHA-256 regardless of the actual hash, causing silent acceptance / rejection mismatches in revocation validation.

### Improved

- **`Iso32000ComplianceTests.Widget_InvisibleHasF0AndZeroRect`** — renamed and updated to assert `/F 132` (reflecting the corrected behaviour); the previous test enshrined the bug.
- **PSS signing is now interoperable with all major validators** — Adobe Acrobat Reader, EU DSS, iText, and eIDAS-compliant validators now accept the produced signatures for PS256, PS384, and PS512 (previously rejected as malformed due to the missing params).

## [0.3.1] - 2026-06-01

### Added

- **DSS merge for multi-signature PDFs** — `LtvEmbedder` now reads existing DSS dictionaries and merges prior VRI entries, CRL/OCSP/Cert object references with new data instead of replacing them. Counter-signatures and multi-party signing workflows now preserve all revocation data.
- **VRI-aware validation path** — `PdfSignatureValidator` computes SHA-1 of each signature's `/Contents` and looks up per-signature VRI entries from the DSS, falling back to global arrays. Enables correct per-signature revocation validation in multi-signer documents.
- **Full DSS extraction** — `DssExtractor.TryReadFullDssDataAsync` returns structured `DssValidationData` with global CRLs/OCSPs/Certs and per-VRI entries (new `DssValidationData` and `VriData` record types).
- **Embedded OCSP validation** — `RevocationChecker` and `OcspClient` now support validating embedded OCSP responses from DSS/VRI without network access (priority: embedded OCSP → embedded CRL → online OCSP → online CRL).
- **CRL issuer certificate chase** — LTV stabilisation loop now detects indirect CRL issuers (issuer DN ≠ cert issuer DN) and fetches their certificates via AIA `caIssuers`, making the loop fully general for all PKI topologies.
- **`CrlClient.ExtractCrlIssuerDn`** — new static method to parse CRL issuer Distinguished Name from DER-encoded CRL bytes.
- **`OcspClient.CheckEmbeddedOcspResponse`** — new instance method for offline OCSP response validation against a target certificate.

### Fixed

- **DSS replacement in multi-signature scenarios** — prior VRI entries and revocation data are no longer lost when adding a second signature with LTV enabled.

## [0.3.0] - 2026-05-25

### Added

- **AI-first documentation** — `llms.txt`, `llms-full.txt` (llmstxt.org standard), `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md` for AI agent discoverability
- **`samples/README.md`** — scenario-to-code index for AI agents and developers
- **ETSI conformance: OcspNoCheck** — OID `1.3.6.1.5.5.7.48.1.5` now prevents infinite recursion in revocation checking (RFC 6960 §4.2.2.2.1)
- **ETSI conformance: OCSP responder certs in DSS** — `OcspClient` returns all responder certificates from OCSP responses for DSS `/Certs` inclusion (Annex A §A.2.2)
- **`TsaCertificateExtractor`** — new utility to extract certificates from RFC 3161 timestamp tokens for DSS inclusion
- **VRI `/TS` stream** — VRI dictionaries now include signature timestamp tokens and `/Type /VRI` (required by ETSI EN 319 142-1)
- **LTV iterative stabilisation** — revocation loop replaced with queue-based stabilisation that chases OCSP responder certs and respects OcspNoCheck
- **Fluent API guards** — `WithLtv()` throws immediately without timestamp; `WithArchivalTimestamp()` throws without LTV

### Fixed

- **VRI key computation** — parses DER length to exclude trailing zero padding, producing correct SHA-1 hashes
- **Certificate deduplication in DSS** — uses thumbprint-keyed map to avoid duplicate embeddings
- **Certificate leak in LtvEmbedder** — duplicate certs now properly disposed in stabilisation loop
- **Double-read in TsaCertificateExtractor** — AsnReader consumption fixed in catch block
- **Double-read in OcspClient** — same fix applied
- **OCSP responder cert disposal** — `ParseOcspResponseWithCerts` wraps in try/catch to dispose on parse failure

### Changed (Breaking)

- **`WithLtv()` now requires `WithTimestamp()`** — calling `.WithLtv()` without a preceding `.WithTimestamp()` throws `InvalidOperationException`
- **`WithArchivalTimestamp()` requires LTV** — calling `.WithArchivalTimestamp()` without `.WithLtv()` throws `InvalidOperationException`
- **`BatchSigner.WithArchivalTimestamp()`** — no longer implicitly enables LTV
- **PDF/A-1 PNG severity** — changed from Warning to Error (absolute prohibition per ISO 19005-1)

### Improved

- **NuGet package metadata** — enhanced `PackageTags` and `Description` for better discoverability by AI agents and package search
- **XML documentation** — added `<example>` tags to `PdfSignatureValidator` and `PdfSignatureInspector`

## [0.2.3] - 2026-05-21

### Fixed (Security)

- **Shadow Attack mitigation** — trailing unsigned content after the last signature's ByteRange is now validated structurally (requires `xref`/cross-reference stream + `startxref` + `%%EOF`); previously only checked for the `%%EOF` string, allowing arbitrary content injection disguised as a valid update
- **Unknown hash OID in signingCertificateV2** — throws `NotSupportedException` instead of silently falling back to SHA-256; prevents an attacker from using a fake algorithm OID to bind a signature to a substitute certificate
- **RSA-PSS NULL parameter** — `SignatureAlgorithmUsesNullParameter` now correctly returns `false` for RSA-PSS (`1.2.840.113549.1.1.10`); RFC 4055 requires `RSASSA-PSS-params`, not NULL; fixes rejection by strict validators (eIDAS, ICP-Brasil Verificador)
- **OCSP CertID verification** — `ParseOcspResponse` now verifies the `CertID` in the response matches the certificate requested (issuerNameHash + serialNumber), as required by RFC 6960 §3.2; single-response fallback preserved for compatibility
- **SSRF DNS rebinding bypass** — `UrlValidator.IsSafeUrl` now resolves hostnames to IP addresses before applying private-range checks, blocking rebinding attacks via domains that resolve to `127.0.0.1` or `169.254.169.254`; IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are also checked
- **`HttpResponseMessage` leak on retry** — `ResilientHttp.Pipeline` now disposes the previous `HttpResponseMessage` in the `OnRetry` callback; previously each 5xx retry leaked a response and its underlying network stream
- **TimestampValidator double-read** — TSA certificate bytes are now read before the `try` block in the ASN.1 loop; a `CryptographicException` on `LoadCertificate` no longer silently consumes the next certificate in the set
- **`PdfByteRange.IsValid` overflow** — added guard for `Offset2 + Length2` overflow; a malformed PDF with near-max values could previously cause `CoversEntireFile` to incorrectly return `true`

### Added

- **`ValidarItiUrlBuilder`** — static helper to generate `https://validar.iti.gov.br/?document=<url>` links for QR code embedding in signed documents
- **CPF/CNPJ on `IcpBrasilValidationResult`** — new properties `Cpf`, `Cnpj`, `CpfFormatted` (`XXX.XXX.XXX-XX`), and `CnpjFormatted` (`XX.XXX.XXX/XXXX-XX`) extracted from the certificate SAN
- **Health professional data** — `IcpBrasilValidationResult.HealthProfessional` exposes CRM/CRO registration number and state code for e-prescriptions (DOC-ICP-04 OIDs `2.16.76.1.3.4`/`.3.5`/`.3.6`)
- **Complete DOC-ICP-15.03 policy OIDs** — `PolicyOids` expanded from 2 to 6 variants per policy level, covering all combinations of version (v1/v2/v3) × certificate type (PF/PJ); previously AD-RB–AD-RA only recognised v3 certs
- **Sponsor button** — `.github/FUNDING.yml` added (GitHub Sponsors via `eupassarin`)

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

[0.3.3]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.3
[0.3.2]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.2
[0.3.1]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.1
[0.3.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.0
[0.2.3]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.3
[0.2.2]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.2
[0.2.1]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.1
[0.2.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.0
