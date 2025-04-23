<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# TODOs 
- Add AlgorithmProfile for LwCMP:
  (ca_kga_logic[ca_kga_logic.py](resources/ca_kga_logic.py),
  validate_senderkid_for_cmp_protection([checkutils.py](resources/checkutils.py).py))
- Restructure code for better readability/identification.
- Add alternative certificate linters.
- FIX KARI ECMQV implementation.
- Decide which is the best way to test EnvelopedData with the `Revocation Passphrase`?
- Verify why the signature verification against pqc-certificates 
for Composite-04 RSA4096-PSS ML-DSA-87 fails.
- Figure out why ECMQV fails for KARI with `BouncyCastle`, but the computation is correct,
RFC5753 says, it also uses ECC_CMS_SHARED_INFO for the KDF.


## About CMP:
1. Add test cases for Section 5.2.1. Requested
   Certificate Contents.
2. Verify the Progress/Coverage for the RFCs.
3. Decide on the RF-Linter settings.
4. Fix the CCR test cases and Mock-CA logic.
5. Add the announcement test cases.
6. Update Logic for testing the Client Implementation
7. Add Semantic-Fuzz-testing.
8. Add clarity for better differentiation between LwCMP and CMP.
9. May integrate Polling test cases.
10. Restructure the test cases for better readability/identification.


## About PQ:

- Add Test cases for FN-DSA, if standard is available.
- Add Stateful Hash-based signature algorithms (XMSS, LMS).

## About Hybrid:

- Maybe check for currently unknown hybrid schemes.
- Keep checking hybrid scheme updates.


## Relevant Literature:


- PQ Certificates:

1. https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/
2. https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/
3. https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-sphincs-plus/

- Hybrid-KEMs:
1. https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
2. https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/
3. https://datatracker.ietf.org/doc/draft-josefsson-chempat/


- Stateful Hash:
1. https://www.rfc-editor.org/rfc/rfc9708.html
2. https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-shbs/13/
