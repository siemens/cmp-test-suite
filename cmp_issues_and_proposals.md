<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->
# CMP Issues and Proposals Template

Use this template to document known issues or proposed enhancements related to CMP (Certificate Management Protocol).

---

| Field                  | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| **Issue**             | <Name of issue or feature>                                                  |
| **Description**       | <Brief explanation of the issue or limitation in current CMP behavior>      |
| **Proposed Fix**      | <Short and clear proposal for how this issue could be addressed>            |
| **Technical Details** | <Relevant technical context, trade-offs, or suggested data structures>       |
| **Coverage in Mock-CA** | Yes / No / Partial (explain briefly if applicable)                         |
| **Tags**              | `<tag1>`, `<tag2>`, ...                                                      |

---

### Example Entry

| Field                  | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| **Issue**             | KGA Parameter Signaling for PQ Stateful Signatures                         |
| **Description**       | Currently, there is no standardized way in CMP to specify algorithm parameters when requesting centrally generated post-quantum stateful signature keys (e.g., XMSS, XMSSMT, HSS). |
| **Proposed Fix**      | Introduce additional algorithm-specific parameter signaling in CMP request messages to allow precise control over centrally generated key types. |
| **Technical Details** | - **For XMSS/XMSSMT**: Add a `univ.Integer` field to signal the XMSS/XMSSMT version (e.g., using OID or height).<br>- **For HSS**: Add integers for LMS depth and LMS/LMOTS types.<br>- Define a new ASN.1 structure or use `SEQUENCE OF INTEGER` in `AlgorithmIdentifier.parameters`. |
| **Coverage in Mock-CA** | No                                                                         |
| **Tags**              | `XMSS`, `XMSSMT`, `HSS`, `PQ-Stateful-Sig`, `CMP`, `KGA`                    |

### Entries

| Field                  | Description                                                                                                                                                                                                                                                                           |
|------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Issue**             | KGA Parameter Signaling for PQ-Stateful-Signatures-Mechanisms                                                                                                                                                                                                                         |
| **Description**       | Currently, there is no standardized way in CMP to specify algorithm parameters when requesting centrally generated post-quantum stateful signature keys (e.g., XMSS, XMSSMT, HSS).                                                                                                    |
| **Proposed Fix**      | Introduce additional algorithm-specific parameter signaling in CMP request messages to allow precise control over centrally generated key types.                                                                                                                                      |
| **Technical Details** | - **For XMSS/XMSSMT**: Add a `univ.Integer` field to signal the XMSS/XMSSMT version (e.g., using OID).<br>- **For HSS**: Add integers for LMS depth and LMS/LMOTS types.<br>- Define a new ASN.1 structure or use `SEQUENCE OF INTEGER` in `AlgorithmIdentifier.parameters`. |
| **Coverage in Mock-CA** | No                                                                                                                                                                                                                                                                                    |
| **Tags**              | `XMSS`, `XMSSMT`, `HSS`, `PQ-Stateful-Sig`, `CMP`, `KGA`                                                                                                                                                                                                                              |

---
