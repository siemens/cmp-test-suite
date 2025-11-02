<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Missing Support Issue Template (Example: HSS Signatures)

The CMP test suite currently lacks support for Hierarchical Signature System (HSS) signatures as defined in RFC 8554 and RFC 9858. 
This includes the ability to parse, validate, and generate HSS signatures and keys. Adding this support is essential for testing 
CMP implementations that utilize HSS for post-quantum security.

## Motivation and Context

- HSS is a widely recognized stateful hash-based signature scheme, offering strong security guarantees.
- CMP implementations may adopt HSS for enhanced security, necessitating comprehensive test coverage.
- Supporting HSS aligns with our goal of providing robust post-quantum cryptographic testing capabilities.

## Desired Support
- Accept, generate, and validate HSS signatures using the parameter sets from RFC 8554, RFC 9858 and NIST SP 800-208.
- Track the HSS hierarchy depth correctly, enforcing `height < 9` and other constraints defined in NIST SP 800-208.

## Required Work Items

1. Extend parsing/validation logic to recognise HSS signature structures and keys.
2. Add regression fixtures (minimal + verbose) covering:
    - Valid signatures across permissible parameter sets.
    - Rejection cases for height ≥ 9, malformed hierarchies, and truncated signatures.
    - Mirror existing XMSS test cases where applicable.
    - Add basic test cases for a slow HSS variant for shake and SHA2 inside [pq_stateful_sig_tests.robot](tests_pq_and_hybrid/pq_stateful_sig_tests.robot).
3. Create verbose tests for all supported HSS combinations with the `scripts/generate_pq_stfl_test_cases.py` script and add it manually.
inside [pq_stateful_sig_alg.robot](tests_pq_and_hybrid/pq_stateful_sig_alg.robot).
4. Update documentation to reflect HSS support.

## Test Coverage

- Update ALGORITHM_TEST_COVERAGE.md to include HSS scenarios.

## Out of Scope/ Should be added later

(if applicable)

## Open Questions / Follow-ups

(if applicable)

## References
- RFC 8554 — Leighton-Micali Hash-Based Signatures.
- RFC 9802 — Use of the HSS and XMSS Hash-Based Signature Algorithms in Internet X.509 PKI.
- RFC 9858 — Additional Parameter Sets for HSS/LMS Hash-Based Signatures.
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes.
