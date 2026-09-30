# ADR 0016: Verifiable AdES Level Fulfillment

**Status:** Accepted (v0.9.0)

**Context:**

ADR 0015 established a shared PAdES, CAdES, and XAdES signing contract in v0.8.0.
The model is retained: immutable format-qualified builders, `AdesBaselineProfile`,
scoped HTTP providers, explicit external signing, and `ISigningResult` remain the
right public architecture. A level reported as achieved, however, must describe the
artifact actually produced. This ADR completes that postcondition.

The following standards are normative for this work:

- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) for timestamp request/response binding;
- [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html) and [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html) for RSA-PSS algorithm and parameter handling;
- [ETSI EN 319 122-1](https://www.etsi.org/deliver/etsi_EN/319100_319199/31912201/01.01.01_60/en_31912201v010101p.pdf) for CAdES archive timestamps;
- [ETSI EN 319 132-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.02.01_60/en_31913201v010201p.pdf) for XAdES archive timestamps.

## Decision

v0.9.0 is a controlled breaking release. It ships only when every level advertised
for a supported format is structurally inspectable and cryptographically bound to
the correct data. Trust-policy evaluation of a TSA remains validation work, but
signing must validate the response binding and embed evidence completely.

### P0 — release blockers

1. **Bind every TSA response to its request.** `TimestampClient` shall require a
   CMS `SignedData` token carrying `TSTInfo`, the expected message-imprint OID and
   bytes, and the exact request nonce. Any structural, imprint, algorithm, or nonce
   mismatch fails closed.
2. **Embed the RFC 3161 token once.** CAdES and XAdES timestamp helpers return raw
   token bytes; their callers embed those bytes once. The embedded token is the same
   token later used to collect TSA validation material.
3. **Construct real archive preimages.** CAdES uses `archiveTimestampV3` with
   `ATSHashIndexV3`; XAdES uses the ETSI `ArchiveTimeStamp` canonicalization and
   reference-processing construction. Passing a serialized container, or a digest
   that a TSA client hashes again, is not conformant.
4. **Require complete LTV evidence.** Collection records certificate, issuer,
   revocation evidence, responder certificates, and absence reason for each signer
   and prior-TSA path. OCSP-to-CRL fallback is per certificate; cancellation is
   never converted into a downgrade.
5. **Inspect the final artifact.** `HasSignatureTimestamp`,
   `HasLongTermValidationMaterial`, `HasArchiveTimestamp`, and `AchievedLevel` are
   based on format-specific final-artifact inspection, not on successful helper
   calls or requested configuration. PAdES verifies the embedded DocTimeStamp
   message imprint against its PDF byte range; CAdES/XAdES verify the archive
   timestamp against their respective ETSI preimages. CAdES/XAdES retain the
   collection ledger and require the final artifact to contain every collected
   certificate and revocation object before treating LTV material as present.
6. **Prove the contract externally.** Builder-produced B-T, B-LT, and B-LTA tests
   use captured TSA tokens and static independent CAdES/XAdES vectors. A validator
   cannot use its generator as its sole oracle.

For v0.9.0, XAdES B-LTA supports the signer-produced topology plus ETSI distributed
unsigned properties addressed by same-document bare-name `Include` references and
preceding counter-signatures. Distributed `Include` processing preserves declared
order and removes comments before canonicalization. External `Include` resources,
ambiguous multi-signature operations, and XMLDSig transforms outside the verified
safe subset fail closed during archive inspection; they never claim B-LTA. CAdES
archive verification processes every `SignerInfo` in a CMS SignedData structure;
the signer currently emits one document signer.

### P1 — terminal-contract completion

1. Replace independently selectable hash and signature OID values with a shared
   resolved signing-algorithm value. It includes scheme, container OID, digest, and
   for RSA-PSS the MGF algorithm/digest, salt length, and trailer field.
2. Extend `ExternalSigningRequest` with that resolved value. Verify external output
   against the certificate public key before packaging it, and document PKCS#1 v1.5,
   PSS, ECDSA DER, and EdDSA raw encodings separately. v0.9.0 explicitly rejects
   EdDSA signing until that raw output can be verified consistently on every target.
3. Reject contradictory combined OID/digest configurations. Allow PSS with a
   conventional `rsaEncryption` key; enforce restrictions only when an
   `id-RSASSA-PSS` public-key identifier contains parameters. Do not confuse absent
   key parameters with ASN.1 default PSS parameters.
4. Normalize completed-configuration errors to `SigningException` with a stable
   reason. Reasonless exceptions use `Unspecified`; cancellation propagates
   unchanged. Certificates are valid only when `NotBefore <= operation time <=
   NotAfter`; `WithSigningTime` remains a signed metadata value and does not bypass
   the real-time credential check.
5. Snapshot all caller-owned PAdES bytes, nested collections, and image buffers.
   Replace nullable clone updates with explicit clearable values. Stream-backed PAdES
   builder lineages are single-use and destination streams are transactional.

### P2 — consistency and documentation

1. `TimestampOptions` and `ArchiveTimestampOptions` accept only absolute HTTP(S)
   endpoints, matching the transport implementation.
2. Update ADR 0015, ADR 0006, ADR 0010, ADR 0012, README, CHANGELOG, and the v0.8 →
   v0.9 migration guide after implementation. The migration guide must show resolved
   algorithm/PSS selection, external signing, stricter levels, and PAdES lifecycle.
3. CAdES/XAdES configure logging only through `WithLogger`. The redundant
   `Document(..., ILogger?)` overload was removed so every format has the same entry
   and fluent-configuration vocabulary.
4. Keep true CAdES streaming deferred. A buffering facade does not deliver streaming
   semantics and is unrelated to evidence correctness.
5. Do not restore v0.7 adapters. Their removal was an intentional v0.8.0 breaking
   change, not a correctness defect.

## Consequences

- Strict success means `RequestedLevel == AchievedLevel` after artifact inspection.
  Best effort is available only through `SignWithDetailsAsync` and reports stable
  downgrade warnings.
- CAdES B-LTA (including archive-index processing for every CMS `SignerInfo`) and the
  supported XAdES B-LTA topologies use
  standards-defined preimages and validate their embedded token coverage.
- The new algorithm model is a public breaking change necessary to eliminate
  ambiguous PSS requests and inconsistent format-specific inference.
- Full trust and policy validation remains outside signing, but request/token binding
  and embedded-evidence completeness are mandatory signing invariants.

## Alternatives considered

| Alternative | Verdict |
| --- | --- |
| Keep B-LTA best effort and add warnings | Rejected: a warning cannot make a false conformance claim truthful. |
| Restore v0.7 compatibility adapters | Rejected: adapters do not repair timestamp, archive, or LTV evidence. |
| Treat raw serialized CMS/XML as archive input | Rejected: neither format matches its ETSI archive construction. |
| Add buffering CAdES streams | Rejected: no actual streaming benefit and distracts from correctness. |
