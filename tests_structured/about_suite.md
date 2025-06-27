<!--
Add copywrite
-->

# About CMP Test Suite
This documentation shall provide guidance if wanted.

## Scope and Documentation 
### Documentation
This document provides the overarching context and limitations of the test suite. It provides an overview of the test suite, including its scope, limitations, and important design considerations. It serves as the entry point for understanding the objectives and constraints of the test suite.

#### Structure_TestSuite
[Structure_TestSuite](Structure_TestSuite.md) outlines the high-level structure of the test suite. It categorizes test cases based on:
- Authentication methods (e.g., signature-based or MAC-based protection).
- Key pair generation methods (e.g., decentral or central key generation).
- Forms of requests (e.g., enrollment, certificate updates, PKCS#10 requests). It provides a roadmap for organizing test cases and links them to relevant sections of RFC 9483. This document complements [About Suite](about_suite.md) by detailing how the test suite is structured and organized.


#### Requirements
[Requirements](Requirements.md) provides detailed functional requirements for each test case. It specifies:
- Prerequisites for each test case.
- Message flows and expected behaviors.
- References to RFC sections that define the requirements. It serves as the blueprint for implementing and validating test cases. While [Structure Test Suite](Structure_TestSuite.md) categorizes test cases, [Requirements](Requirements.md) delves deeper into the specifics of each test case, ensuring alignment with RFC standards.

#### Test Case Files (*.robot)
These files contain the actual implementation of the test cases described in [Requirements](Requirements.md). Each test case is tagged and documented to align with the categories and requirements outlined in [Structure Test Suite](Structure_TestSuite.md) and [Requirements](Requirements.md).

### How the documents work together
[About Suite](about_suite.md) provides the overarching context and limitations of the test suite.
[Structure Test Suite](Structure_TestSuite.md) organizes the test cases into categories and links them to relevant RFC sections.
[Requirements](Requirements.md) defines the functional requirements for each test case, ensuring compliance with RFC standards.
Test Case Files (*.robot) implement the test cases based on the requirements and structure defined in the other documents.
Together, these documents form a cohesive framework for testing CMP implementations. They ensure that the test suite is well documented, organized, and aligned with industry standards.

### Limitations of the test suite

| Limitation        | Description                                                                                        |
|--------------------|----------------------------------------------------------------------------------------------------|
| CoAP Not Supported| CoAP is not supported (RFC 9482 CMP over CoAP).                                                   |
| RFC 6712 Lax      | Only basic tests are available due to RFC 6712 being lax.                                         |
| Upstream PKI      | Anything that is upstream within the PKI Management Entity, as we can only test reactions of the PKI Management Entity with this test suite |
| RFC9483 5.2       | These are specific descriptions of processes within a PKI Management Entity. The test suite only looks at the reactions towards the end entity |

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