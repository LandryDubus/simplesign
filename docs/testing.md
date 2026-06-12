# Testing

SimpleSign's test suite provides comprehensive coverage across cryptographic operations, PDF parsing, signature validation, PDF/A compliance, and cross-platform interop verification. All cryptography uses only `System.Security.Cryptography` -- no third-party crypto dependencies.

---

## Overview

| Test layer | Projects | Purpose |
|---|---|---|
| **Unit** | 5 projects | Core crypto, PDF parsing, PAdES signing/validation, ICP-Brasil, HTML-to-PDF |
| **Integration** | 1 project | Network-dependent operations (OCSP, CRL, TSA) |
| **Interop** | 1 project | Cross-platform signature verification (VeraPDF, PDF.js, iText, Adobe Reader) |
| **CLI** | 1 project | CLI tool integration tests (Spectre.Console output, exit codes) |
| **Fuzzing** | 1 workspace | 7 fuzz targets via SharpFuzz, run weekly |
| **Smoke** | 1 project | Native AOT compilation verification |
| **Mutation** | Stryker (all unit) | Advanced-level mutation testing, min. 50% break threshold |

---

## Project breakdown

### Unit tests (`tests/unit/`)

| Project | What it tests | Approx. tests |
|---|---|---|
| `SimpleSign.Core.Tests` | Crypto primitives, CMS builder, TSA client, OCSP/CRL, HTTP, URL validation | ~300 |
| `SimpleSign.Pdf.Tests` | PDF parser (xref, objects, streams, incremental save) | ~110 |
| `SimpleSign.PAdES.Tests` | PAdES signing pipeline, validation, inspection, PDF/A preservation, appearance | ~630 |
| `SimpleSign.Brasil.Tests` | ICP-Brasil chain validation, CPF/CNPJ extraction, Gov.br assurance levels | ~50 |
| `SimpleSign.HtmlToPdf.Tests` | HTML-to-PDF layout engine | ~60 |

All unit tests must complete in under 5 seconds and require zero network access.

### Integration tests (`tests/integration/`)

Tests that require network access: live TSA requests, OCSP/CRL fetches against real certificates, and end-to-end signing workflows against public timestamp authorities.

### Interop tests (`tests/interop/`)

Cross-platform signature verification matrix:
- **VeraPDF** -- PDF/A conformance validation (ISO 19005)
- **PDF.js** -- Browser-based signature inspection
- **iText** -- Java-based PDF signing and validation
- **Adobe Reader** -- Reference implementation verification

Requires Docker for VeraPDF: `docker pull verapdf/cli`

### CLI tests (`tests/cli/`)

Integration tests for the `simplesign` CLI tool, validating Spectre.Console output format, exit codes, argument parsing, and file I/O.

### Fuzz tests (`tests/fuzz/`)

7 fuzz targets for parsing robustness, run weekly via `.github/workflows/fuzz.yml`:
- PDF parser (xref, objects, streams, cross-reference table, incremental saves, and more)

### Smoke tests (`tests/smoke/`)

AOT compilation verification: `dotnet publish tests/smoke/SimpleSign.AotSmokeTest -r linux-x64` ensures the library is fully native-AOT compatible (no reflection, no `dynamic`, no `Assembly.Load`).

### Mutation tests

Stryker.NET configured at `Advanced` mutation level, running against the full codebase. Thresholds:
- **High:** 80 (`stryker-config.json`)
- **Low:** 60
- **Break:** 50 (build fails if mutation score drops below this)

---

## Running tests

### All unit tests

```bash
dotnet test tests/unit/
```

### Specific project

```bash
dotnet test tests/unit/SimpleSign.PAdES.Tests
```

### Specific category

```bash
# Stress tests only
dotnet test --filter "Category=Stress"

# Exclude stress tests (default CI path)
dotnet test --filter "Category!=Stress"

# Interop: VeraPDF
dotnet test tests/interop/ --filter "Category=VeraPdf"
```

### Mutation tests

```bash
dotnet stryker
```

### AOT smoke test

```bash
dotnet publish tests/smoke/SimpleSign.AotSmokeTest -r linux-x64
```

---

## CI quality gates

Every push and pull request to `main`/`develop` triggers:

1. **Build** (0 warnings, 0 errors) -- Windows, macOS, Ubuntu
2. **Unit tests** -- all platforms, excluding stress category
3. **Coverage** (Ubuntu only) -- `coverlet` output + report upload
4. **Mutation testing** -- Stryker.NET on Ubuntu, enforces 50% break threshold
5. **Stress tests** -- parallel execution under load (separate job)
6. **Fuzzing** -- weekly schedule (all 7 targets, 5 min each)

---

## Test guidelines

- **Framework:** xUnit -- use `Assert.*` methods
- **Naming:** `MethodName_Condition_ExpectedResult`
- **Certificates:** use `TestCertificateGenerator` from test helpers (never real certificates)
- **No network:** unit tests must not require network access
- **Deterministic:** tests must not depend on random values or system time
- **No warnings as errors:** the entire build enforces 0 warnings
