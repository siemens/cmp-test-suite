<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# About CMP Test Suite
The test suite focuses on testing the reactions of the PKI Management Entity to various CMP operations initiated by End 
Entities (EEs). It ensures compliance with RFC specifications and validates the behavior of the PKI Management Entity under 
different scenarios, including enrollment, certificate updates, revocation, and message handling.

## Scope and Documentation 
### Documentation
This document provides the overarching context and limitations of the test suite. It provides an overview of the test suite, including its scope, limitations, and important design considerations. It serves as the entry point for understanding the test suite's objectives and constraints.

#### Structure_TestSuite
[Structure_TestSuite](Structure_TestSuite.md) outlines the high-level structure of the test suite. It categorizes test cases based on:
- Authentication methods (e.g., signature-based or MAC-based protection).
- Key pair generation methods (e.g., decentral or central key generation).
- Forms of requests (e.g., enrollment, certificate updates, PKCS#10 requests). It provides a roadmap for organizing test cases and links them to relevant sections of RFC 9483. This document complements [About Suite](about_suite.md) by detailing how the test suite is structured and organized.


#### Requirements
[Requirements](Requirements.md) provides detailed functional requirements for each test case. It specifies:
- Prerequisites for each test case.
- Message flows and expected behaviors.
- References to RFC sections that define the requirements. It serves as the blueprint for implementing and validating test cases. While [Structure Test Suite](Structure_TestSuite.md) categorizes test cases, [Requirements](Requirements.md) dives deeper into the specifics of each test case, ensuring alignment with RFC standards.

#### Test Case Files (*.robot)
These files contain the actual implementation of the test cases described in [Requirements](Requirements.md). Each test case is tagged and documented to align with the categories and requirements outlined in [Structure Test Suite](Structure_TestSuite.md) and [Requirements](Requirements.md).

### How the documents work together
[About Suite](about_suite.md) provides the overarching context and limitations of the test suite.
[Structure Test Suite](Structure_TestSuite.md) organizes the test cases into categories and links them to relevant RFC sections.
[Requirements](Requirements.md) defines the functional requirements for each test case, ensuring compliance with RFC standards.
Test Case Files (*.robot) implement the test cases based on the requirements and structure defined in the other documents.
Together, these documents form a cohesive framework for testing CMP implementations. They ensure that the test suite is well-documented, organized, and aligned with industry standards.

### Limitations of the test suite

| Limitation        | Description                                                                                        |
|--------------------|----------------------------------------------------------------------------------------------------|
| CoAP Not Supported| CoAP is not supported (RFC 9482 CMP over CoAP).                                                   |
| RFC 6712 Lax      | Only basic tests are available due to RFC 6712 being lax.                                         |
| Upstream PKI      | Anything that is upstream within the PKI Management Entity, as we can only test reactions of the PKI Management Entity with this test suite |
| RFC9483 5.2       | These are specific descriptions of processes within a PKI Management Entity. The test suite only lookes at the reactions towards the end entity |

---


## Important Design Understandings

| Notes | Description                                                                                                                                                                                                                                                                                         |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1     | If MAC-based protection is disabled, an initial certificate and its corresponding private key must be provided.                                                                                                                                                                                     |
| 2     | The first issued certificate will be used for all other requests.                                                                                                                                                                                                                                   |
| 3     | Ensure the complete certificate chain is returned so the root certificate (trust anchor) can be saved to `data/trustanchors`.                                                                                                                                                                       |
| 4     | For the first issued certificate, the chain is saved to `./data/cert_logs` for valid requests.                                                                                                                                                                                                      |
| 5     | If the `implicitConfirm` extension is not allowed, a valid `CertConf` must be processed correctly.                                                                                                                                                                                                  |
| 6     | For most tests, the **"ir"** body is used because it is the mandatory body.                                                                                                                                                                                                                         |
| 7     | A default body will be used for MAC-based protection.                                                                                                                                                                                                                                               |
| 8 | Because some setups may only allow one sender, but not the same key, or may allow only one certificate per user, every test will append a number to the sender name (if not specified in the config). This number is incremented each time a test case uses an underlying function that performs this action. |

---

## Tag Descriptions
The enumeration of tags is not complete. 

#### Setup

| Tag    | Description                                                                                                     |
|--------|-----------------------------------------------------------------------------------------------------------------|
| lwcmp  | Tests the Lightweight Certificate Management Protocol, designed for constrained resource environments.         |

---

#### PKIMessage

| Tag        | Description                                                                                                       |
|------------|-------------------------------------------------------------------------------------------------------------------|
| extraCert  | Additional certificates included in a message to facilitate the validation of a certificate chain.              |

---

#### PKIHeader

| Tag             | Description                                                                                              |
|------------------|----------------------------------------------------------------------------------------------------------|
| rfc9483-header  | Tests related to the `PKIHeader` description in RFC 9483, Section 3.                                      |
| headers         | Tests for all header fields.                                                                             |
| sender          | Tests only related to the `sender` field.                                                                |
| senderKID       | Tests only related to the `senderKID` field.                                                             |
| senderNonce     | Tests only related to the `senderNonce` field.                                                           |
| time            | Tests only related to the `messageTime` field.                                                           |
| implicit_confirm| Tests related to the `implicitConfirm` inside the `generalInfo` field.                                   |
| protectionAlg   | Tests related to the `protectionAlg` field.                                                              |

---

#### PKIBody

| Tag            | Description                                                                                             |
|-----------------|-------------------------------------------------------------------------------------------------------|
| kup            | Tests specifically related to the `Key Update Response` body.                                         |
| kur            | Tests specifically related to the `Key Update Request` body.                                          |
| ip             | Tests specifically related to the `Initialization Response` body.                                     |
| ir             | Tests specifically related to the `Initialization Request` body.                                      |
| cp             | Tests related only to the `Certification Response` body.                                              |
| cr             | Tests related only to the `Certification Request` body.                                               |
| rr             | Tests related to the `Revocation or Revive Request` body.                                             |
| general-message| Tests related to the `General Message` body.                                                          |
| batching       | Tests related to processing multiple certificate requests in a single batch.                          |
| certConf       | Tests related to the `Certificate Confirmation` body.                                                 |

---

#### About: Issuing/Revocation

| Tag             | Description                                                                                           |
|------------------|-------------------------------------------------------------------------------------------------------|
| csr             | Tests related only to CSR (Certificate Signing Request).                                             |
| add-info        | Tests related to missing additional information in requests or responses.                            |
| adding-protection| Tests for RFC 9483, Section 5.2.2.1.                                                                |
| ak              | **[Skipped]**                                                                                        |
| bad-behaviour   | Indicates improper or non-compliant behavior in protocol operations.                                  |
| validity        | Tests related to the validity period of a certificate to be issued.                                  |

---

#### Extensions

| Tag                | Description                                                                                        |
|---------------------|----------------------------------------------------------------------------------------------------|
| extended-key-usage | Tests whether the CA issued the certificate with the `extended-key-usage` extension.               |
| extensions         | Tests related to certificate extensions.                                                           |
| basic-constraints  | Tests whether the `basic-constraints` extension is included and validated during issuance.         |

---

#### Security

| Tag          | Description                                                                                              |
|--------------|----------------------------------------------------------------------------------------------------------|
| inconsistency| Detection of mismatches or conflicts within protocol data or operations.                                |
| key          | Tests related to key management, from issuing to correct usage.                                         |
| mac          | Tests related to MAC-based protection.                                                                  |
| signature    | Tests related to signature-based protection.                                                            |
| trust        | Tests related to trust (e.g., `raVerified from an EE`).                                                 |

---

#### Support Messages

| Tag                | Description                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------------|
| ca-certs           | Description not provided.                                                                        |
| get_cert_template  | Description not provided.                                                                        |
| get_root_ca_cert_update| Description not provided.                                                                     |

---

#### Extras

| Tag               | Description                                                                                         |
|--------------------|-----------------------------------------------------------------------------------------------------|
| rfc6712           | Reference to RFC 6712, which defines rules for CMP over HTTP.                                      |
| rfc9483-header    | Header information specific to the RFC 9483 protocol.                                              |
| rfc9483-validation| Validation processes and checks as defined by RFC 9483.                                           |

---
