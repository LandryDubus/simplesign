# ADR 0003: Result Objects for Validation (Not Exceptions)

**Status:** Accepted (permanent)

**Context:**
Signature validation involves many checks (integrity, certificate chain, revocation, timestamps). Throwing exceptions for validation failures would make it hard to aggregate multiple issues, distinguish error levels, and provide actionable feedback.

**Decision:**
Validation never throws for expected failures. Instead, it returns structured result objects (`SignatureValidationResult`, `BatchValidationResult`) with:

- Lists of errors, warnings, and informational messages
- Structured fields for each validation aspect (integrity, chain, revocation, timestamp)
- Success/failure summary

Exceptions are only thrown for programming errors (null arguments, invalid configuration) or I/O failures.

**Consequences:**
- Callers can inspect all validation results, not just the first failure
- Validation is safe to use in CI pipelines (no exception handling needed)
- Batch validation across multiple PDFs is straightforward
- Slightly more complex API surface than a simple boolean

**Status:** This decision is permanent. Validation will always return results, not throw.
