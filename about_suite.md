<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

### How the Test Suite Operates

#### Important Design Understandings

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

### Tag Descriptions

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

#### Custom Tags

| Tag               | Description |
|--------------------|-------------|
|            |             |

---

#### Limitations

| Limitation        | Description                                                                                        |
|--------------------|----------------------------------------------------------------------------------------------------|
| CoAP Not Supported| CoAP is not supported (RFC 9482 CMP over CoAP).                                                   |
| RFC 6712 Lax      | Only basic tests are available due to RFC 6712 being lax.                                         |

---

#### TODOs

**Verify Order**

| #   | Task Description                                                                         | Status              | Notes                                  |
|-----|------------------------------------------------------------------------------------------|---------------------|----------------------------------------|
| 1   | Add PQ and Hybrid Mechanism.                                                             | Covered             |                                        |
| 2   | Add some new features from rfc4210bis-15                                                 | In Progress         |                                        |
| 3   | Better logic for non-signing keys.                                                       | Covered             |                                        |
| 4   | Get Feedback for future improvements.                                                    | Pending             |                                        |
| 5   | Update Logic for testing the Client Implementation                                       | Unknown if interested | Verified by Alex                       |
| 6   | Add Tool for better doc generation.                                                      | Pending             |                                        |
| 7   | Add Semantic-Fuzz-testing.                                                               | Pending             |                                        |
| 8   | Add clarity for better differentiation between LwCMP and CMP.                            | Pending             |                                        |
| 9   | Add CMP only logic.                                                                      | Pending             |                                        |
| 10  | May integrate Polling test cases.                                                        | Pending             |                                        |


