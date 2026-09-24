# Interop Testing

This directory contains the cross-implementation validation infrastructure for SimpleSign. It runs ~150 test scenarios against 8 independent verifiers across 18 test files to ensure signatures produced by SimpleSign are correctly validated by third-party tools, and vice versa.

## Features

- ~150 automated test scenarios across 18 test files
- Forward interop: SimpleSign signatures → external verifiers
- Reverse interop: external tool signatures → SimpleSign validation
- Docker-based isolated environments for reproducibility
- CI integration (weekly schedule + manual dispatch)

## Verifiers

| Verifier | Pinned version | Purpose | Directory |
|----------|----------------|---------|-----------|
| OpenSSL | 3.5.8-r0 | CMS/PKCS#7 signature verification | `dss-validator/` |
| xmlsec1 | 1.3.11-r0 | W3C XML-DSig verification | `dss-validator/` |
| pyHanko | 0.37.0 | PAdES-level PDF validation | `dss-validator/` |
| Apache PDFBox | 3.0.8 | PDF structure and signature inspection | `pdfbox/` |
| EU DSS | 6.5 | ETSI EN 319 102 conformance validation | `eu-dss/` |
| iText | 9.7.1 | Independent PAdES validation | `itext/` |
| veraPDF CLI | image digest `sha256:d5ee329657cf9bc4b2400392dd54c7d0a0ce9980ff6fa2da5590eebeec007cdb` | PDF/A conformance after incremental signing | test code |
| pyHanko-sign | 0.37.0 | Reverse interop (external → SimpleSign) | `dss-validator/` |

These were the latest stable releases available when reviewed on 2026-09-24.

## Reproducibility policy

- Docker base images and externally run validator images are pinned by immutable manifest digest. A readable tag is retained alongside each digest.
- Direct Java, Python, NuGet, and downloaded JAR dependencies use exact versions. The complete Python dependency graph is recorded in `dss-validator/requirements.txt`.
- Downloaded standalone artifacts are checksum-verified; the PDFBox JAR uses Docker's `ADD --checksum` guard.
- GitHub Actions are pinned to full commit SHAs, with the corresponding release tag in a comment.
- Version updates are deliberate: resolve the newest stable release, update the version and digest/checksum together, rebuild every image, and run the interop suite before merging.
- Maven and NuGet verify repository-provided artifact hashes during restore. Their transitive graphs are governed by the exact direct dependency POM/package versions; generated lock files are not currently used.

## Running Locally

```bash
# Build Docker images
docker build -t simplesign-dss dss-validator
docker build -t simplesign-eu-dss eu-dss
docker build -t simplesign-itext itext
docker build -t simplesign-pdfbox pdfbox

# The veraPDF image is referenced directly by digest in the tests
docker pull verapdf/cli@sha256:d5ee329657cf9bc4b2400392dd54c7d0a0ce9980ff6fa2da5590eebeec007cdb

# Run all interop tests
dotnet test tests/interop/
```

## See Also

- [Main README](../README.md)
- [Interoperability Documentation](../docs/interoperability.md)
- [EU DSS Validator](eu-dss/README.md)
- [iText Validator](itext/README.md)
