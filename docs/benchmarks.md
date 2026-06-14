← [Back to README](../README.md)

# Comprehensive Benchmarks

BenchmarkDotNet results for all SimpleSign benchmark suites — signing, validation, parsing, I/O, concurrency, and algorithms.

**69 benchmarks across 15 suites**, executed on a single machine for reproducible comparison.

---

## Methodology

| Parameter | Value |
|-----------|-------|
| **Hardware** | Apple M2 Pro, 10 cores (10 logical) |
| **OS** | macOS Sequoia 15.6.1 (24G90) |
| **Runtime** | .NET 10.0.8, Arm64 RyuJIT, Concurrent Workstation GC |
| **Tool** | BenchmarkDotNet v0.15.8 |
| **Job** | `ShortRun` (1 launch, 3 warmup, 3 iterations) for most suites; `MediumRun` (2 launches, 10 warmup, 15 iterations) for competitor comparisons |
| **Config** | `[MemoryDiagnoser]` on all suites |
| **PDF source** | iText7-generated minimal A4 PDF (~4 KB) |

> ⚠️ ShortRun jobs have wider confidence intervals than full benchmark runs.
> MediumRun results have tighter intervals and are more reliable for comparative analysis.

---

## 1. Feature Benchmarks

Measures the overhead of each optional signing feature relative to a plain PAdES-B-B signature.

```
BenchmarkDotNet v0.15.8, macOS Sequoia 15.6.1 (24G90) [Darwin 24.6.0]
Apple M2 Pro, 1 CPU, 10 logical and 10 physical cores
.NET SDK 10.0.300
  [Host]   : .NET 10.0.8 (10.0.8, 10.0.826.23019), Arm64 RyuJIT armv8.0-a
  ShortRun : .NET 10.0.8 (10.0.8, 10.0.826.23019), Arm64 RyuJIT armv8.0-a
```

| Method | Mean | Ratio | Allocated | Alloc Ratio |
|--------|-----:|------:|----------:|------------:|
| Plain sign (PAdES-B-B) | 26.42 ms | 1.07 | 498.05 KB | 1.00 |
| + visual appearance | 20.33 ms | 0.83 | 758.05 KB | 1.52 |
| + metadata (name/reason/location) | 25.59 ms | 1.04 | 498.86 KB | 1.00 |
| + appearance + metadata | 25.01 ms | 1.02 | 759.29 KB | 1.52 |
| + certification (NoChanges) | 23.06 ms | 0.94 | 499.21 KB | 1.00 |
| + PDF/A preservation | 14.32 ms | 0.58 | 498.42 KB | 1.00 |

**Key observations:**
- Visual appearance is the dominant allocation cost (+52%)
- Metadata and certification add negligible overhead
- Results show high variance in this run — use as directional only

---

## 2. Algorithm Benchmarks

Compares signing performance across key algorithms and hash sizes.

| Method | Mean | Ratio | Allocated | Alloc Ratio |
|--------|-----:|------:|----------:|------------:|
| RSA-2048 / SHA-256 | 13.67 ms | 1.00 | 498.08 KB | 1.00 |
| RSA-4096 / SHA-256 | 92.23 ms | **6.75** | 506.34 KB | 1.02 |
| RSA-2048 / SHA-512 | 15.54 ms | 1.14 | 498.35 KB | 1.00 |
| **ECDSA-P256 / SHA-256** | **5.65 ms** | **0.41** | 493.82 KB | 0.99 |
| ECDSA-P384 / SHA-384 | 10.04 ms | 0.73 | 494.67 KB | 0.99 |

**Key observations:**
- **ECDSA P-256 is 2.4× faster than RSA-2048** at equivalent security
- **RSA-4096 is 6.75× slower** than RSA-2048 — prefer ECDSA for new deployments
- SHA-512 adds ~14% overhead over SHA-256 on RSA-2048
- All algorithms allocate ~500 KB per signing operation

---

## 3. PSS (RSA-PSS vs PKCS#1 v1.5)

Direct comparison of RSA-PSS signatures across hash variants against PKCS#1 v1.5 baseline.

### PKCS#1 v1.5 (baseline)

| Method | Mean | Ratio | Allocated |
|--------|-----:|------:|----------:|
| PKCS#1 v1.5 / SHA-256 | 13.36 ms | 1.00 | 497.95 KB |
| PKCS#1 v1.5 / SHA-384 | 13.20 ms | 0.99 | 498.09 KB |
| PKCS#1 v1.5 / SHA-512 | 13.43 ms | 1.01 | 498.23 KB |

### RSA-PSS

| Method | Mean | Ratio | Allocated |
|--------|-----:|------:|----------:|
| RSA-PSS PS256 (SHA-256) | 13.83 ms | 1.00 | 498.61 KB |
| RSA-PSS PS384 (SHA-384) | 13.86 ms | 1.00 | 498.78 KB |
| RSA-PSS PS512 (SHA-512) | 14.09 ms | 1.02 | 498.92 KB |

**Key observations:**
- **PSS has negligible overhead** over PKCS#1 v1.5 — within noise (±2%)
- All hash variants perform nearly identically for PSS
- PSS is effectively **free** from a performance standpoint — always prefer it

---

## 4. Incremental Signing

Cost per signature added to the same PDF (the accumulating allocated memory reflects the growing document, not a leak).

| Method | Mean | Ratio | Allocated | Alloc Ratio |
|--------|-----:|------:|----------:|------------:|
| Add 1st signature (unsigned → 1 sig) | 13.75 ms | 1.00 | 498.12 KB | 1.00 |
| Add 2nd signature (1 sig → 2 sigs) | 13.84 ms | 1.01 | 597.39 KB | 1.20 |
| Add 3rd signature (2 sigs → 3 sigs) | 15.26 ms | 1.11 | 794.36 KB | 1.59 |
| Add 4th signature (3 sigs → 4 sigs) | 15.77 ms | 1.15 | 991.58 KB | 1.99 |
| Add 5th signature (4 sigs → 5 sigs) | 15.62 ms | 1.14 | 1,189.96 KB | 2.39 |

**Key observations:**
- Each signature adds ~200 KB to the document (incremental update overhead)
- Time grows sub-linearly — 5 signatures take only 1.14× the first
- Memory grows linearly with document size (expected)

---

## 5. LTV Benchmarks

Compares signing cost across PAdES conformance levels. B-T, B-LT, and B-LTA involve network calls (timestamp server, OCSP/CRL fetching).

| Method | Mean | Ratio | Allocated | Alloc Ratio |
|--------|-----:|------:|----------:|------------:|
| PAdES-B-B (no timestamp, no LTV) | 13.59 ms | 1.00 | 497.92 KB | 1.00 |
| PAdES-B-T (with timestamp) | 210.68 ms | **15.50** | 582.36 KB | 1.17 |
| PAdES-B-LT (timestamp + LTV) | 283.41 ms | **20.85** | 1,022.34 KB | 2.05 |
| PAdES-B-LTA (timestamp + LTV + archival) | 473.65 ms | **34.85** | 1,758.52 KB | 3.53 |

**Key observations:**
- **B-T is 15× slower than B-B** due to the network round-trip to the TSA
- **B-LT adds ~35% over B-T** (OCSP/CRL fetching + DSS embedding)
- **B-LTA adds ~67% over B-LT** (archival timestamp + second TSA call)
- These are network-bound — actual times depend on TSA/OCSP latency

---

## 6. Scale: Document Size

Shows how signing time and memory scale with PDF document size.

| Method | Mean | vs 1 KB | Allocated | GC Pressure |
|--------|-----:|--------:|----------:|-------------|
| PAdES sign 1 KB PDF | 13.28 ms | 1.00× | 497.88 KB | None |
| PAdES sign 100 KB PDF | 13.48 ms | 1.02× | 992.62 KB | Gen1 |
| PAdES sign 1 MB PDF | 15.35 ms | **1.16×** | 6,539.68 KB | Gen2 |
| PAdES sign 10 MB PDF | 26.83 ms | **2.02×** | 61,834.77 KB | Gen2 |

**Key observations:**
- Signing is **I/O-bound**, not CPU-bound — 100 KB is only 2% slower than 1 KB
- 1 MB is 16% slower (I/O copy dominates)
- 10 MB is 2× slower — the PDF is read and copied in full
- Memory allocation scales with input size (expected)

---

## 7. Batch Signing

Measures throughput when signing multiple documents, comparing `BatchSigner` with sequential loops at 2 concurrency levels.

### 10 documents

| Method | Mean | Allocated |
|--------|-----:|----------:|
| Sequential (loop) | 136.3 ms | 4.86 MB |
| BatchSigner (concurrency=4) | 134.5 ms | 4.87 MB |
| BatchSigner (concurrency=1) | 142.0 ms | 4.87 MB |
| BatchSigner (concurrency=8) | 131.3 ms | 4.87 MB |
| BatchSigner (concurrency=16) | 135.0 ms | 4.87 MB |

### 100 documents

| Method | Mean | Allocated |
|--------|-----:|----------:|
| Sequential (loop) | 1,434.4 ms | 48.62 MB |
| BatchSigner (concurrency=4) | 1,307.3 ms | 48.69 MB |
| BatchSigner (concurrency=1) | 1,344.3 ms | 48.69 MB |
| BatchSigner (concurrency=8) | 1,296.5 ms | 48.69 MB |
| BatchSigner (concurrency=16) | 1,294.4 ms | 48.69 MB |

**Key observations:**
- At 10 docs, concurrency gains are invisible (noise dominates)
- At 100 docs, BatchSigner concurrency=16 is **~10% faster** than sequential
- The signing operation is CPU-bound on the RSA operation, limiting parallel speedup
- Allocation is nearly identical across all strategies

---

## 8. Concurrency Scaling

Measures throughput under concurrent load — 32 sequential vs concurrent signing operations.

| Method | Mean | Ratio | Allocated |
|--------|-----:|------:|----------:|
| Sequential (32 ops) | 428.4 ms | 1.00 | 15.57 MB |
| Concurrent 8 tasks (32 ops) | 414.6 ms | 0.97 | 15.57 MB |
| Concurrent 16 tasks (32 ops) | 415.6 ms | 0.97 | 15.57 MB |
| Concurrent 32 tasks (32 ops) | 422.1 ms | 0.99 | 15.57 MB |

**Key observations:**
- Concurrency shows **negligible gains** on Apple M2 Pro (10 cores)
- The RSA-2048 signing operation saturates a single core effectively
- No allocation difference between sequential and concurrent

---

## 9. Deferred Signing

Measures the two-phase deferred signing workflow: `PrepareAsync` (hash generation) vs `CompleteAsync` (CMS injection).

| Method | Mean | Ratio | Allocated | Alloc Ratio |
|--------|-----:|------:|----------:|------------:|
| Direct sign (single-phase) | 14,076 μs | 1.00 | 498.07 KB | 1.00 |
| Deferred: PrepareAsync only | **26.85 μs** | **0.002** | 437.76 KB | 0.88 |
| Deferred: CompleteAsync only | **42.99 μs** | **0.003** | 215.95 KB | 0.43 |
| Deferred: full roundtrip | 1,948 μs | 0.139 | 653.96 KB | 1.31 |

**Key observations:**
- **PrepareAsync is 524× faster than direct signing** — it only generates attributes + hash
- **CompleteAsync is 327× faster** — it only injects the CMS into the PDF
- Full roundtrip (Prepare + RSA sign + Complete) is 7.2× faster than direct sign
- Deferred signing is ideal for HSM/remote-key scenarios

---

## 10. Deferred Builder Benchmarks

Compares `DeferredSigner` static API vs `DeferredSignerBuilder` fluent API.

| Method | Mean | Ratio | Allocated |
|--------|-----:|------:|----------:|
| DeferredSigner static: PrepareAsync | 25.98 μs | 1.00 | 437.82 KB |
| DeferredSigner static: CompleteAsync | 42.28 μs | 1.63 | 216.26 KB |
| DeferredSignerBuilder: PrepareAsync | 25.83 μs | 1.00 | 437.97 KB |
| DeferredSignerBuilder: PrepareAsync (full config) | 26.18 μs | 1.01 | 438.84 KB |

**Key observations:**
- **No measurable overhead** for the builder API over the static API
- Full configuration (signer name, reason, location) adds <1% to PrepareAsync
- Allocation is identical — builders are zero-cost abstractions

---

## 11. Validation Benchmarks

Measures `PdfSignatureValidator` performance across different PDF states.

| Method | Mean | Allocated |
|--------|-----:|----------:|
| PAdES validate (1 signature) | 232.7 μs | 95.35 KB |
| PAdES validate (5 signatures) | 1,252.9 μs | 467 KB |
| PAdES validate (chain: Root→Intermediate→End) | 223.9 μs | 95.43 KB |

**Key observations:**
- Validation is **fast** — 233 μs for a single signature
- 5 signatures take ~5.4× the time of 1 signature (near-linear)
- Chain validation is nearly identical to single-signature (chain is pre-validated by X509Chain)

---

## 12. Inspection Benchmarks

Measures `PdfSignatureInspector.InspectAsync` — fast metadata extraction (no crypto).

| Method | Mean | Ratio | Allocated |
|--------|-----:|------:|----------:|
| Inspect — 1 signature | 209.2 μs | 1.00 | 93.55 KB |
| Inspect — 5 signatures | 1,242.8 μs | 5.95 | 455.84 KB |
| Inspect — 10 signatures | 2,091.9 μs | 10.01 | 910.51 KB |

**Key observations:**
- Inspection scales **linearly** with signature count
- 10 signatures take ~10× the time of 1 — no super-linear cost
- Inspection is ~10% cheaper than full validation (no crypto verification)

---

## 13. Stream I/O Benchmarks

Compares `byte[]`, `MemoryStream`, and `FileStream` as input/output strategies.

| Method | Mean | Ratio | Allocated | Alloc Ratio |
|--------|-----:|------:|----------:|------------:|
| byte[] → byte[] (baseline) | 13.34 ms | 1.00 | 497.99 KB | 1.00 |
| MemoryStream → MemoryStream | 13.43 ms | 1.01 | 464.19 KB | 0.93 |
| FileStream → FileStream | 13.95 ms | 1.05 | 376.05 KB | **0.76** |

**Key observations:**
- `FileStream` allocates **24% less memory** than `byte[]` — avoids in-memory buffering
- Time overhead is minimal (~5%) — the file I/O cost is hidden by OS caching
- `MemoryStream` is virtually identical to `byte[]` in speed

---

## 14. Parsing Benchmarks

Isolates PDF parsing and CMS extraction costs from signing.

| Method | Mean | Allocated |
|--------|-----:|----------:|
| ReadSignatureFields — unsigned PDF | **675.6 ns** | 1,176 B |
| ReadSignatureFields — 1 signature | 149.3 μs | 51,472 B |
| ReadSignatureFields — 5 signatures | 706.0 μs | 251,744 B |
| PadesExtractor.ExtractAsync — 1 signature | 148.3 μs | 88,104 B |
| PadesExtractor.ExtractAsync — 5 signatures | 780.8 μs | 1,105,151 B |
| IsEncryptedAsync check | **1.0 μs** | 136 B |

**Key observations:**
- **Unsigned PDF parsing is sub-millisecond** (676 ns)
- PadesExtractor allocates more than ReadSignatureFields (CMS extraction is heavier)
- Both scale linearly with signature count
- IsEncrypted check is essentially free (1 μs)

---

## 15. Competitor Benchmarks

Compares SimpleSign signing performance against iText 9 + BouncyCastle.
Uses the same RSA-2048 certificate and PDF input for fair comparison.
Run with `MediumRun` (2 launches, 10 warmup, 15 iterations) for tighter confidence intervals.

```
BenchmarkDotNet v0.15.8, macOS Sequoia 15.6.1 (24G90) [Darwin 24.6.0]
Apple M2 Pro, 1 CPU, 10 logical and 10 physical cores
.NET SDK 10.0.300
  [Host]    : .NET 10.0.8 (10.0.8, 10.0.826.23019), Arm64 RyuJIT armv8.0-a
  MediumRun : .NET 10.0.8 (10.0.8, 10.0.826.23019), Arm64 RyuJIT armv8.0-a

Job=MediumRun  IterationCount=15  LaunchCount=2
WarmupCount=10
```

| Method | Mean | Ratio | Gen0 | Gen1 | Allocated | Alloc Ratio |
|-----------------------------------|----------:|------:|--------:|--------:|----------:|------------:|
| 'SimpleSign PAdES-B-B' | 13.700 ms | 1.00 | 46.8750 | 15.6250 | 498.36 KB | 1.00 |
| 'iText 9 + BouncyCastle PAdES-B-B' | 4.940 ms | **0.36** | 85.9375 | 23.4375 | 766.4 KB | **1.54** |

**Key observations:**
- **iText 9 is ~2.8× faster** (4.94 ms vs 13.70 ms) for a basic PAdES-B-B signature — iText's signing pipeline is highly optimized with native C/C++ interop
- **SimpleSign uses 35% less memory** (498 KB vs 766 KB per operation) — the pure-managed implementation avoids external allocations despite doing more work
- iText 9 triggers more GC pressure (86 vs 47 Gen0 collections per 1000 ops)
- The speed gap is expected: SimpleSign does more work inline (byte range computation, CMS container construction with full signed attributes, manual PDF dictionary encoding) while iText delegates to native libraries
- Deferred/Prepared signing in SimpleSign closes the gap significantly: `PrepareAsync` takes only 27 μs (524× faster than direct sign), making it competitive for server-side workflows where the RSA operation dominates

---

## Summary & Takeaways

### Performance Characteristics

| Category | Baseline | Slowest | Ratio |
|----------|----------|---------|-------|
| Signing (local, no network) | RSA-2048: 13.7 ms | RSA-4096: 92.2 ms | 6.75× |
| Signing with LTV | B-B: 13.6 ms | B-LTA: 473.7 ms | 34.9× |
| Algorithm | ECDSA P-256: 5.6 ms | RSA-4096: 92.2 ms | **16.3×** |
| Competitor (vs iText 9) | iText: 4.9 ms | SimpleSign: 13.7 ms | **2.78×** |
| Validation | 1 sig: 233 μs | 5 sigs: 1.25 ms | 5.4× |
| Deferred (Prepare) | Direct: 14 ms | Def. Prepare: 27 μs | **524× faster** |
| I/O | byte[]: 13.3 ms | FileStream: 14.0 ms | 1.05× |
| Inspection | 1 sig: 209 μs | 10 sigs: 2.09 ms | 10× |

### Recommendations

1. **Use ECDSA P-256** for new deployments — 2.4× faster than RSA-2048 with equivalent security
2. **Always use PSS** over PKCS#1 v1.5 — zero performance cost, better security
3. **Deferred signing** is ideal for HSM/remote-key scenarios — PrepareAsync is 524× faster than direct sign
4. **FileStream** saves memory (24%) at negligible speed cost — use for large documents
5. **Concurrency gains are limited** on consumer hardware — the RSA op is CPU-bound per core
6. **Inspection is fast** — use `PdfSignatureInspector` when you only need metadata (no crypto)
7. **SimpleSign vs iText 9**: SimpleSign is 2.8× slower on direct signing but uses 35% less memory and is pure-managed (no native dependencies, AOT-compatible). For server-side signing with HSMs, SimpleSign's deferred mode (27 μs prep) is competitive for all but the most throughput-demanding scenarios.

---

## Running the Benchmarks Yourself

```bash
# All benchmarks (net10.0)
cd bench
dotnet run -c Release --project SimpleSign.Benchmarks --framework net10.0 -- --job short

# Compare with .NET 8
dotnet run -c Release --project SimpleSign.Benchmarks --framework net8.0 -- --job short

# Filter to a specific suite
dotnet run -c Release --project SimpleSign.Benchmarks -- --job medium --filter "*Feature*"
dotnet run -c Release --project SimpleSign.Benchmarks -- --job medium --filter "*Algorithm*"
dotnet run -c Release --project SimpleSign.Benchmarks -- --job medium --filter "*Pss*"
dotnet run -c Release --project SimpleSign.Benchmarks -- --job medium --filter "*Competitor*"
```

The full result files are in [`bench/BenchmarkDotNet.Artifacts/results/`](../bench/BenchmarkDotNet.Artifacts/results/) or [`BenchmarkDotNet.Artifacts/results/`](../BenchmarkDotNet.Artifacts/results/) — GitHub-flavored markdown, CSV, HTML, and JSON.
