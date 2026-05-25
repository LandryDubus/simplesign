# AGENTS.md — Instructions for AI Coding Agents

> This file provides instructions for autonomous AI coding agents (GitHub Copilot Workspace, OpenAI Codex, Devin, etc.) working on the SimpleSign repository.

## Quick Reference

| Action | Command |
|--------|---------|
| Build all | `dotnet build` |
| Unit tests | `dotnet test tests/unit/` |
| Specific tests | `dotnet test tests/unit/SimpleSign.PAdES.Tests` |
| Integration tests | `dotnet test tests/integration/` |
| Lint/format check | Build with 0 warnings (enforced) |
| AOT smoke test | `dotnet publish tests/smoke/SimpleSign.AotSmokeTest -r linux-x64` |

## Project Structure

```
SimpleSign/
├── src/                          Production code
│   ├── SimpleSign.Core/          Crypto: CMS, TSA, OCSP, CRL, hashing
│   ├── SimpleSign.Pdf/           PDF parser: xref, objects, incremental save
│   ├── SimpleSign.PAdES/         PAdES signing, validation, inspection
│   ├── SimpleSign.Brasil/        ICP-Brasil extensions
│   ├── SimpleSign.HtmlToPdf/     HTML→PDF layout engine
│   └── ...
├── tests/
│   ├── unit/                     Unit tests (~1,600 tests, < 5s)
│   ├── integration/              Network-dependent tests
│   ├── interop/                  Cross-platform signature verification
│   ├── smoke/                    AOT compilation smoke test
│   └── shared/                   Test fixtures & helpers
├── samples/                      Example applications
├── docs/                         Documentation (docfx)
├── Directory.Build.props         Shared MSBuild properties
└── global.json                   SDK version (10.0.100)
```

## Build System

- **SDK:** .NET 10 (global.json pins to 10.0.100)
- **Targets:** net8.0 and net10.0 (multi-target)
- **Language:** C# 13
- **Analysis:** All rules enabled, warnings as errors
- **Style:** Enforced in build (IDE0022, IDE0011, IDE0055 are errors)

## Code Quality Rules

These will cause build failures:
- Missing braces on `if`, `foreach`, `while`, `for` (IDE0011)
- Expression-bodied members where block body should be used (IDE0022)
- Formatting violations (IDE0055)
- Any compiler warning (TreatWarningsAsErrors=true)
- Missing XML documentation on public members
- Nullable reference type warnings

## Testing Guidelines

- Framework: xUnit
- Naming: `MethodName_Condition_ExpectedResult`
- Assertions: use xUnit `Assert.*` methods
- Don't commit real certificates — use `TestCertificateGenerator` from test helpers
- Unit tests must not require network access
- Tests should be deterministic (no random, no time-dependent)

## PR Guidelines

- Branch from `main`
- Run `dotnet build` and `dotnet test tests/unit/` before submitting
- Keep commits focused (one concern per commit)
- Don't modify `Directory.Build.props` without good reason
- Update CHANGELOG.md for user-visible changes
- Add/update tests for any behavior changes

## Architecture Decisions

- **No third-party crypto:** All cryptographic operations use `System.Security.Cryptography`
- **AOT compatible:** No reflection-based serialization, no `dynamic`, no `Assembly.Load`
- **No unsafe code:** `AllowUnsafeBlocks=false` everywhere
- **Incremental PDF save:** Signatures append to the PDF without modifying existing bytes
- **Async-first:** All I/O operations are async (TSA, OCSP, CRL fetches)
- **Result objects for validation:** Validation never throws — returns structured results

## Common Tasks

### Adding a new signing option
1. Add property to the builder in `SimpleSign.PAdES`
2. Thread it through to `PdfSigner`
3. Add unit tests
4. Update XML docs and README example

### Adding a new validation check
1. Add to `ValidationOptions` if configurable
2. Implement in validator pipeline
3. Add to `ValidationResult` fields
4. Add tests (both valid and invalid cases)

### Fixing a PDF parsing issue
1. Reproduce with a test PDF in `tests/shared/SimpleSign.TestFixtures`
2. Add a failing test first
3. Fix in `SimpleSign.Pdf`
4. Verify with interop tests if cross-platform relevant
