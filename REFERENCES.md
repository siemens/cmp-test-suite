# References

<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

This section lists external specifications and internal documents that may be helpful
when working with the Mock CA.

## Table of Contents

- [References](#references)
  - [Project Documentation](#project-documentation)
  - [Standards](#standards)
    - [Transport CMP](#transport-cmp)
    - [Algorithm Profiles](#algorithm-profiles)
    - [Drafts](#drafts)
  - [Software](#software)
  - [Post-Quantum Key Encapsulation Mechanism (KEM)](#post-quantum-key-encapsulation-mechanism-kem)
    - [ML-KEM](#ml-kem)
      - [Related RFCs and Drafts](#related-rfcs-and-drafts)
  - [Post-Quantum Signature](#post-quantum-signature)
    - [ML-DSA](#ml-dsa)
      - [Related RFCs and Drafts](#related-rfcs-and-drafts-1)
    - [SLH-DSA](#slh-dsa)
      - [Related RFCs and Drafts](#related-rfcs-and-drafts-2)
  - [PQ Stateful Signature](#pq-stateful-signature)
    - [XMSS / XMSSMT](#xmss--xmssmt)
    - [HSS](#hss)
  - [Hybrid Key Encapsulation Mechanism (KEM)](#hybrid-key-encapsulation-mechanism-kem)
  - [Hybrid Signature](#hybrid-signature)
  - [Hybrid Certificates](#hybrid-certificates)

---

## Project Documentation

- [Server Test Coverage](./SERVER_TEST_COVERAGE.md)
- [CMP Test Suite README](./readme.md)
- [Post‑Quantum Integration Details](./about_pq.md)
- [Test Suite Architecture](./about_suite.md)
- [CMP Issues and Proposals](./cmp_issues_and_proposals.md)
- [Mock CA README](./MockCA_readme.md)

## Standards

- [RFC 4210 — Certificate Management Protocol (CMP)](https://datatracker.ietf.org/doc/rfc4210/)
- [RFC 9480 — Certificate Management Protocol (CMP) Updates](https://datatracker.ietf.org/doc/rfc9480/)
- [RFC 9483 — Lightweight Certificate Management Protocol (CMP)](https://datatracker.ietf.org/doc/rfc9483/)
- [RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://datatracker.ietf.org/doc/rfc5280/)

### Transport CMP

- [RFC 6712 — CMP over HTTP](https://datatracker.ietf.org/doc/rfc6712/)
- [RFC 9482 — CMP over CoAP](https://datatracker.ietf.org/doc/rfc9482/)

### Algorithm Profiles

- [RFC 9481 — CMP Algorithms](https://datatracker.ietf.org/doc/rfc9481/)

### Drafts

- [draft-ietf-lamps-rfc4210bis (CMP)](https://datatracker.ietf.org/doc/draft-ietf-lamps-rfc4210bis/)

## Software

- [OpenSSL](https://www.openssl.org/docs/) — command-line tools used for CSR generation and CMP messages
- [liboqs](https://github.com/open-quantum-safe/liboqs) — post-quantum cryptography library enabling PQ algorithms

## Post-Quantum Key Encapsulation Mechanism (KEM)

### ML-KEM

- [FIPS 203 — Module-Lattice-based Key-Encapsulation Mechanism (ML-KEM)](https://doi.org/10.6028/NIST.FIPS.203)

#### Related RFCs and Drafts

- [draft-ietf-lamps-kyber-certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/) — X.509 certificate profile for ML‑KEM
- [draft-ietf-lamps-cms-kyber](https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-kyber/) — Using ML‑KEM in CMS

## Post-Quantum Signature

### ML-DSA

- [FIPS 204 — Module-Lattice-based Digital Signature Algorithm (ML‑DSA)](https://doi.org/10.6028/NIST.FIPS.204)

#### Related RFCs and Drafts

- [draft-ietf-lamps-dilithium-certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/) — X.509 certificate profile for ML‑DSA
- [draft-ietf-lamps-cms-ml-dsa](https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-ml-dsa/) — Using ML‑DSA in CMS

### SLH-DSA

- [FIPS 205 — Stateless Hash‑Based Digital Signature Algorithm (SLH‑DSA)](https://doi.org/10.6028/NIST.FIPS.205)

#### Related RFCs and Drafts

- [RFC 9814 — Use of the SLH‑DSA Signature Algorithm in CMS](https://datatracker.ietf.org/doc/rfc9814/)
- X.509 certificate profile for SLH‑DSA:
  - [draft-ietf-lamps-sphincsplus-certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-sphincsplus-certificates/)

## PQ Stateful Signature

- NIST Special Publication:
  - [NIST SP 800‑208 — Recommendation for Stateful Hash‑Based Signature Schemes](https://doi.org/10.6028/NIST.SP.800-208)
- Defines the use of XMSS and HSS in X.509:
  - [RFC 9802 — Use of the HSS and XMSS Hash‑Based Signature Algorithms in Internet X.509 Public Key Infrastructure](https://datatracker.ietf.org/doc/rfc9802/)

### XMSS / XMSSMT

- Definition of XMSS and XMSSMT:
  - [RFC 8391 — XMSS: eXtended Merkle Signature Scheme](https://datatracker.ietf.org/doc/rfc8391/)

### HSS

- Definition of LMS and HSS:
  - [RFC 8554 — Leighton–Micali Hash‑Based Signatures](https://datatracker.ietf.org/doc/rfc8554/)
- Using LMS/HSS in CMS:
  - [RFC 9708 — Use of the HSS/LMS Hash‑Based Signature Algorithm in the Cryptographic Message Syntax (CMS)](https://datatracker.ietf.org/doc/rfc9708/)
- Additional parameter sets for HSS/LMS hash‑based signatures:
  - [draft-fluhrer-lms-more-parm-sets](https://datatracker.ietf.org/doc/draft-fluhrer-lms-more-parm-sets/)

## Hybrid Key Encapsulation Mechanism (KEM)

- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [draft-ietf-lamps-pq-composite-kem](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/)
- [draft-josefsson-chempat](https://datatracker.ietf.org/doc/draft-josefsson-chempat/)

## Hybrid Signature

- [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)

## Hybrid Certificates

- [draft-sun-lamps-hybrid-scheme](https://datatracker.ietf.org/doc/draft-sun-lamps-hybrid-scheme/)
- [RFC 9763 — Related Certificates for Use in Multiple Authentications within a Protocol](https://datatracker.ietf.org/doc/rfc9763/)
- [draft-lamps-okubo-certdiscovery](https://datatracker.ietf.org/doc/draft-lamps-okubo-certdiscovery/)
- [draft-bonnell-lamps-chameleon-certs](https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/)
- Catalyst (Alternative Signature):
  - [ITU‑T X.509 (10/2019) — Alternative public key and signature extensions](https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/CertificateExtensions.html)
  - Document:
    - [ITU‑T X.509 (10/2019)]( https://www.itu.int/ITU-T/recommendations/rec.aspx?id=14033)
  - Died draft:
    - [draft-truskovsky-lamps-pq-hybrid-x509 — Multiple Public‑Key Algorithm X.509 Certificates](https://datatracker.ietf.org/doc/draft-truskovsky-lamps-pq-hybrid-x509/)
