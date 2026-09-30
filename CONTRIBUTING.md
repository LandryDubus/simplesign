# Contributing to SimpleSign

Thank you for your interest in contributing to SimpleSign! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (for full test matrix)
- Docker (optional, for interop tests)

### Building

```bash
git clone https://github.com/eupassarin/SimpleSign.git
cd simplesign
dotnet restore
dotnet build
```

### Running Tests

```bash
# Build the complete multi-target solution
dotnet build SimpleSign.sln

# Specific project
dotnet test tests/unit/SimpleSign.PAdES.Tests

# Cross-format signing contract
dotnet test tests/unit/SimpleSign.Contracts.Tests

# With coverage
dotnet test --collect:"XPlat Code Coverage" --settings coverlet.runsettings

# Interop tests (requires Docker)
dotnet test tests/interop/SimpleSign.Interop.Tests --filter Category=Interop
```

## How to Contribute

### Reporting Bugs

Open an issue with:
- A clear title and description
- Steps to reproduce
- Expected vs actual behavior
- .NET version and OS

### Suggesting Features

Open an issue with the `enhancement` label. Describe:
- The use case
- Proposed API (if applicable)
- Any alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run the focused project tests and affected interop tests
5. Ensure the solution has no warnings (`dotnet build SimpleSign.sln` — warnings are errors)
6. Submit a pull request

### Code Style

- The project uses `TreatWarningsAsErrors=true` and `AnalysisMode=All`
- Nullable reference types are enabled globally
- Follow the existing immutable builder pattern for new signing APIs
- All public methods must have XML documentation (`<summary>`, `<param>`, `<returns>`)
- Async methods must accept `CancellationToken cancellationToken = default`
- Use `ConfigureAwait(false)` on all `await` calls in library code
- Prefer `[LoggerMessage]` source-generated logging over manual `ILogger` calls

### Test Guidelines

- Use xUnit `[Fact]` / `[Theory]` with behavior-oriented test names
- Use the assertion library already referenced by the target test project
- Tests requiring Docker, network or external TSA services must be explicitly categorized and skippable
- Cryptographic changes require positive and negative artifact tests; ADeS changes also require independent vectors when available
- Add `[Trait("Category", "...")]` for slow, network, or interop tests

### Commit Messages

Use clear, descriptive commit messages. Include a `Co-authored-by` trailer when applicable.

## Project Structure

```
src/
  SimpleSign.Core/      # Core crypto, caching, revocation, extension points
  SimpleSign.Pdf/       # PDF structure parsing
  SimpleSign.CAdES/     # CAdES signing, validation, inspection
  SimpleSign.XAdES/     # XAdES signing, validation, inspection
  SimpleSign.PAdES/     # PAdES signing, validation, inspection
  SimpleSign.Brasil/    # ICP-Brasil / Gov.br extensions
  SimpleSign.HtmlToPdf/ # HTML-to-PDF converter
  SimpleSign/           # Meta-package (all capabilities)
tests/
  unit/SimpleSign.*.Tests/       # Unit tests
  integration/SimpleSign.*.Tests/ # Network-dependent integration tests
  interop/SimpleSign.Interop.Tests/ # External compatibility tests
  fuzz/SimpleSign.Fuzz/          # Fuzz testing harness
bench/
  SimpleSign.Benchmarks/ # BenchmarkDotNet performance tests
interop/
  dss-validator/        # EU DSS Docker image for interop testing
  pdfbox/               # Apache pdfbox Docker image
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
