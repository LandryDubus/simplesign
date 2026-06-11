# Releasing a New Version

Step-by-step guide for releasing a new SimpleSign version.

## Pre-release Checklist

- [ ] All changes are committed on `main`
- [ ] `dotnet build` passes with 0 warnings
- [ ] `dotnet test tests/unit/SimpleSign.PAdES.Tests --framework net10.0` — all pass
- [ ] `dotnet test tests/unit/SimpleSign.Core.Tests --framework net10.0` — all pass
- [ ] `dotnet test tests/unit/SimpleSign.Pdf.Tests --framework net10.0` — all pass

## Version Bump Locations

Update the version string in **all** of these files:

| File | Property | Notes |
|------|----------|-------|
| `Directory.Build.props` | `<Version>` | Global default for all projects |
| `src/SimpleSign/SimpleSign.csproj` | `<Version>` | Meta-package |
| `src/SimpleSign.Core/SimpleSign.Core.csproj` | `<Version>` | Core crypto |
| `src/SimpleSign.Pdf/SimpleSign.Pdf.csproj` | `<Version>` | PDF parser |
| `src/SimpleSign.PAdES/SimpleSign.PAdES.csproj` | `<Version>` | Main package |
| `src/SimpleSign.Brasil/SimpleSign.Brasil.csproj` | `<Version>` | ICP-Brasil |
| `src/SimpleSign.HtmlToPdf/SimpleSign.HtmlToPdf.csproj` | `<Version>` | HTML→PDF |
| `src/SimpleSign.HostSigner/SimpleSign.HostSigner.csproj` | `<Version>` | Host signer |
| `src/SimpleSign.Cli/SimpleSign.Cli.csproj` | `<Version>` | CLI tool |

### Quick sed command (macOS):
```bash
VERSION="X.Y.Z"
OLD="0.4.0"
sed -i '' "s/<Version>$OLD</<Version>$VERSION</g" \
  Directory.Build.props \
  src/SimpleSign/SimpleSign.csproj \
  src/SimpleSign.Core/SimpleSign.Core.csproj \
  src/SimpleSign.Pdf/SimpleSign.Pdf.csproj \
  src/SimpleSign.PAdES/SimpleSign.PAdES.csproj \
  src/SimpleSign.Brasil/SimpleSign.Brasil.csproj \
  src/SimpleSign.HtmlToPdf/SimpleSign.HtmlToPdf.csproj \
  src/SimpleSign.HostSigner/SimpleSign.HostSigner.csproj \
  src/SimpleSign.Cli/SimpleSign.Cli.csproj
```

## Documentation Updates

### CHANGELOG.md
Add a new section at the top (below the header), following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...

### Changed (Breaking)
- ... (only if applicable)
```

### README.md
Update the `## What's New in vX.Y.Z` section (around line 30) with highlights of this release.

### Other files to check
```bash
# Verify no stale version references remain:
grep -r "OLD_VERSION" --include="*.txt" --include="*.md" --include="*.yml" . | grep -v node_modules | grep -v obj/ | grep -v bin/ | grep -v CHANGELOG
```

## Build & Test

```bash
dotnet build
dotnet test tests/unit/SimpleSign.PAdES.Tests --framework net10.0
dotnet test tests/unit/SimpleSign.Core.Tests --framework net10.0
dotnet test tests/unit/SimpleSign.Pdf.Tests --framework net10.0
```

## Commit & Tag

```bash
git add Directory.Build.props CHANGELOG.md README.md src/*/SimpleSign.*.csproj src/SimpleSign/SimpleSign.csproj
git commit -m "chore: bump version to X.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

## Publish NuGet Packages

```bash
dotnet pack -c Release -o ./artifacts
# Then push each .nupkg to NuGet.org:
dotnet nuget push ./artifacts/SimpleSign.Core.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.Pdf.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.PAdES.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.Brasil.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.HtmlToPdf.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
```

## GitHub Release

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file - << 'NOTES'
## What's New

(paste highlights from CHANGELOG.md)
NOTES
```

## Versioning Policy

- **PATCH** (0.4.x): Bug fixes, performance, internal improvements, new non-breaking features
- **MINOR** (0.x.0): New public API surface, deprecations
- **MAJOR** (x.0.0): Breaking changes to public API

Current version: `0.4.0`
