# ADR 0007: Multi-targeting (.NET 8 + .NET 10)

**Status:** Accepted

**Context:**
.NET libraries must choose which runtime versions to support. The trade-off is between:

- **Broader adoption** — .NET 8 LTS (Nov 2023) has wide deployment in enterprise environments and will remain supported until Nov 2026
- **Newer APIs** — .NET 9+ introduced SHA-3 hashing, EdDSA digital signatures, `X509CertificateLoader` (AOT-safe cert loading), and improved performance
- **Maintenance cost** — conditional compilation (`#if NET9_0_OR_GREATER`) adds branching logic and doubles the test matrix

.NET 10 (Nov 2025) is the current STS release with further improvements.

**Decision:**
Target **both** `net8.0` and `net10.0` via multi-targeting in `Directory.Build.props`:

```xml
<TargetFrameworks>net8.0;net10.0</TargetFrameworks>
```

.NET 9+ features are conditionally compiled:

```csharp
#if NET9_0_OR_GREATER
_ when alg == HashAlgorithmName.SHA3_256 => Oids.Sha3_256,
#endif
```

**Consequences:**

- .NET 8 users get full functionality (PAdES B-B/T/LT/LTA, all algorithms except SHA-3 and EdDSA signing)
- .NET 9+ users get SHA-3 hashing (SHA3-256/384/512) and EdDSA verification
- `X509CertificateLoader` used on .NET 9+ (avoids deprecated `X509Certificate2` constructors)
- Test matrix doubled — every test runs twice (once per TFM)
- `#if NET9_0_OR_GREATER` guards require discipline: new .NET 9+ features must be properly guarded
- Code that compiles on both TFMs but behaves differently must be tested on both
- Build times increase (~2x for multi-targeting projects)
- NuGet packages contain both TFMs, increasing package size
- HostSigner remains net8.0-windows only (Windows-specific, no need for .NET 10)

**Drop criteria:**
- net8.0 will be dropped when it reaches end of support (Nov 2026) AND adoption metrics show migration to .NET 10+
- net10.0 will be dropped when net12.0 is added (always support latest STS + current LTS)

**Alternatives considered:**

| Strategy | Pros | Cons | Verdict |
|----------|------|------|---------|
| **net8.0 only** | Simpler build, one test run | No SHA-3, no EdDSA, deprecated APIs | Rejected — too limiting |
| **net10.0 only** | Clean code, latest APIs | Excludes enterprise .NET 8 users | Rejected — too narrow |
| **Multi-target (chosen)** | Best of both | Maintenance overhead | **Chosen** |
| **net8.0 + net9.0 + net10.0** | Max coverage | Triple build cost, net9 STS redundancy | Rejected — net10 already covers net9 APIs |

**Status:** This decision is accepted and will be reviewed when .NET 8 reaches EOL (Nov 2026).
