# ADR 0002: Incremental PDF Save (Append-Only)

**Status:** Accepted (permanent)

**Context:**
PDF signatures require that the original document bytes are preserved exactly. Any modification to existing bytes invalidates the ByteRange hash. Approaches include: rewriting the entire PDF (complex, error-prone) or appending an incremental update with the signature dictionary and signature value.

**Decision:**
SimpleSign uses incremental PDF saves: the signature is appended to the end of the PDF file as a new revision. The original bytes (ByteRange 1 and ByteRange 2) are never modified.

**Consequences:**
- Signatures survive linear append operations
- Multiple signatures can be layered (up to 100+ revisions)
- PDF/A conformance preserved (incremental updates are allowed per ISO 19005)
- Simple implementation: copy input to output, append xref and objects
- File size grows with each signature (small incremental addition)
- Cannot remove signatures (by design — digital signatures are append-only)

**Status:** This decision is permanent. Rewrite-based signing will not be implemented.
