# ADR 0006: External Signer / Deferred Signing

**Status:** Accepted

**Context:**
Many real-world signing scenarios require the private key to remain on a separate device or service:

- **HSM** (Hardware Security Module) — key never leaves the device
- **Smart cards** (ICP-Brasil, eID) — key on physical token
- **Web applications** — key in browser (WebCrypto), hash signed server-side
- **Mobile apps** — key in secure enclave (iOS Secure Enclave, Android Keystore)
- **Cloud KMS** — AWS KMS, Azure Key Vault, Google Cloud KMS

Traditional signing libraries assume the private key is loaded into process memory. SimpleSign needed an architecture that works when the key is *external*.

**Decision:**
Two complementary patterns, both supporting AOT compatibility:

### 1. External Signer (`WithExternalSigner` callback)

For scenarios where the caller controls the full signing operation:

```csharp
.WithExternalSigner(async (hash, hashAlgorithm, cert) =>
{
    // Sign hash with external key, return CMS signature bytes
    return await hsm.SignAsync(hash, hashAlgorithm);
})
```

The callback receives the computed hash + algorithm and must return a complete DER-encoded CMS `SignedData`. SimpleSign embeds the returned CMS into the PDF.

### 2. Deferred Signing (`DeferredSigner.PrepareAsync` + `CompleteAsync`)

For web/mobile scenarios where server and client are separate:

```
Server                          Client
──────                          ──────
PrepareAsync(pdf, cert)
→ hashToSign + sessionData
                                  Sign(hashToSign)
                                  → raw signature
CompleteAsync(sessionData, sig)
→ signed.pdf
```

The `sessionData` is an opaque blob that encodes the PDF state between phases. The private key never travels over the network — only the hash digest.

**Consequences:**

- Private key isolation: key never enters SimpleSign process memory
- AOT-safe: callbacks use `Func<>` delegates, no dynamic invocation
- `DeferredSigner` requires stateful session management (opaque blob approach chosen over session IDs to avoid server-side storage dependency)
- Algorithm inference: both paths auto-detect hash algorithm from certificate unless overridden
- Timestamp hash: `CompleteAsync` derives timestamp hash from the CMS digest OID
- External signer must produce CMS — caller needs ASN.1/DER knowledge
- Deferred session data is not encrypted (caller is responsible for secure storage)
- EdDSA (Ed25519/Ed448) only supported via external signer path (no BCL API for direct EdDSA signing)

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| **Session IDs + server storage** | Simpler API | Requires persistent storage, cleanup complexity, scaling issues | Rejected |
| **Opaque blob (chosen)** | Stateless, no server storage | Blob can be large (~100 KB with full PDF state) | **Chosen** |
| **SignedInfo for pre-signed CMS** | Standards-compliant (RFC 5652) | More complex implementation, not supported by all HSMs | Rejected |

**Status:** This decision is accepted. Both patterns will remain the primary way to sign with external/remote keys.
