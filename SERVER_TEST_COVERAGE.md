<!--    
SPDX-FileCopyrightText: Copyright 2025 Siemens AG    
    
SPDX-License-Identifier: Apache-2.0    
-->
# Test Coverage
## Table of Contents
- [Test Coverage Server](#test-coverage-server)
    - [RFC 9483 LwCMP](#rfc-9483-lwcmp)
        - [PKIHeader Section 3.1](#pkiheader-section-31)
        - [SIG PKIProtection Section 3.2](#sig-pkiprotection-section-32)
        - [3.3 Section Handling `extraCerts`](#33-section-handling-extracerts)
        - [3.5 Section Generic `PKIMessage` Validation](#35-section-generic-pkimessage-validation)
        - [Certificate Request Validation (Section 4.1-4.1.4)](#certificate-request-validation-section-41-414)
        - [Extensions Coverage](#extensions-coverage)
        - [Individual Test Cases – Section 4.1](#individual-test-cases-section-41)
    - [Individual Test Cases](#individual-test-cases)
    - [Section 4.1](#section-41)
    - [Section 4.1.1](#section-411)
    - [Section 4.1.2](#section-412)
    - [Section 4.1.3](#section-413)
    - [Section 4.1.4](#section-414)
        - [Section 4.1.5 MAC-Based Enrollment](#section-415-mac-based-enrollment)
    - [Enrollment Scenarios](#enrollment-scenarios)
    - [Section 4.1.6](#section-416)
        - [Section 4.1.6.1](#section-4161)
        - [Section 4.1.6.2](#section-4162)
        - [Section 4.1.6.3](#section-4163)
- [Certificate Confirmation and PKI Confirmation Test Coverage](#certificate-confirmation-and-pki-confirmation-test-coverage)
    - [Certificate Confirmation Validation (RFC 9483 §4.1)](#certificate-confirmation-validation-rfc-9483-41)
    - [PKI Confirmation Response (RFC 9483 §3 & §4.1)](#pki-confirmation-response-rfc-9483-3-41)
    - [Individual Test Cases](#individual-test-cases)
    - [RFC 9483 Section 4.2 Revocation Coverage](#rfc-9483-section-42-revocation-coverage)
        - [Individual Test Cases Revocation](#individual-test-cases-revocation)
    - [Coverage Section 4.3](#coverage-section-43)
        - [Section 4.3.1](#section-431)
        - [Section 4.3.2](#section-432)
        - [Section 4.3.3](#section-433)
        - [Section 4.3.4](#section-434)
    - [Coverage Section 5.2](#coverage-section-52)
        - [5.2.2.1 Adding Protection](#5221-adding-protection)
        - [5.2.2.2 Batching Messages](#5222-batching-messages)
        - [5.2.3.2 Using `raVerified`](#5232-using-raverified)

# Test Coverage Server
## RFC 9483 LwCMP

### PKIHeader Section 3.1

| Header field                | Validation checks covered                                                                | Body types **covered**                                                       | Body types **missing**                  | Files                                     |     |  
| --------------------------- |------------------------------------------------------------------------------------------| ---------------------------------------------------------------------------- | --------------------------------------- | ----------------------------------------- | --- |  
| **pvno**                    | invalid value (!= 2 or 3)                                                                | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, added_protection, `batch`   | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **sender**                  | invalid type (not`directoryName` MAC) , set to issuer (SIG), invalid subject (SIG)       | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **senderKID**               | missing (MAC & SIG), invalid (MAC & SIG)                                                 | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **messageTime**             | missing, outside allowed window, too old                                                 | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **protectionAlg** (MAC/SIG) | MAC-alg mismatch, SIG-alg mismatch, inkonsistent (MAC & SIG)                             | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **senderNonce**             | missing, too short (< 16 B), too long (> 16 B)                                           | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **recipNonce**              | present, matching to senderNonce                                                         | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **implicitConfirm**         | `present and used`, `invalid value`, clashes with `confirmWaitTime`, present not allowed | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **confirmWaitTime**         | UTCTime used, clashes with `implicitConfirm`                                             | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| **Full PKIHeader**          | valid header for negative and positive cases                                             | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |     |  
| senderNonce, recipNonce     | matching senderNonce / recipNonce                                                        | `certConf`,`pkiconf`                                                         | added_prot_cert_conf, batched_cert_conf | cert_conf_test.robot                      |     |  


### SIG PKIProtection Section 3.2

> **Note**: Those test cases were created by a Python script at `./script/generate_pki_prot_tests.py`.

| Key Algorithm (PKIProtection) | Validation Checks Covered                        | Hash Algorithms                                                                            | Body Types **Covered** | Reference          | Files                                 | Section Reference  |     |  
| ----------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------ | ---------------------- | ------------------ | ------------------------------------- | ------------------ | --- |  
| **Ed25519**                   | Valid signature, Invalid signature               | (implicit in Ed25519)                                                                      | `ir` (template)        | RFC 9481           | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481           |     |  
| **Ed448**                     | Valid signature, Invalid signature               | (implicit in Ed448)                                                                        | `ir` (template)        | RFC 9481           | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481           |     |  
| **RSA**                       | Valid signature, Invalid signature, BadAlg(SHA1) | SHA1[^1], SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512           | `ir` (template)        | RFC 9481, RFC 9688 | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481, RFC 9688 |     |  
| **RSA-PSS**                   | Valid signature, Invalid signature               | SHA256, SHAKE128, SHAKE256                                                                 | `ir` (template)        | RFC 9481           | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481           |     |  
| **ECDSA**                     | Valid signature, Invalid signature,              | SHA224, SHA256, SHA384, SHA512, SHAKE128, SHAKE256, SHA3-224, SHA3-256, SHA3-384, SHA3-512 | `ir` (template)        | RFC 9481, RFC 9688 | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481, RFC 9688 |     |  

[^1]: SHA1 is considered weak and is marked as `BadAlg(SHA1)` due to known cryptographic vulnerabilities.
    
---    
### 3.3 Section Handling `extraCerts`

| Check area                                    | Validation checks covered                                                                         | File                |  
| --------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------- |  
| Protection certificate at index 0.            | • `extraCerts` must include the full certificate chain with the protection certificate at index 0 | `tests/lwcmp.robot` |  
| Signature protection **without** `extraCerts` | • Signature‑protected requests missing the certificate chain are rejected                         | `tests/lwcmp.robot` |  
| Incomplete certificate chain.                 | • Requests that include only the end‑entity certificate in `extraCerts` are rejected              | `tests/lwcmp.robot` |  
  ---    
### 3.5 Section Generic `PKIMessage` Validation

| Check area               | Validation checks covered                                                          | File                |  
| ------------------------ | ---------------------------------------------------------------------------------- | ------------------- |  
| Unrecognized algorithms  | • Requests using unknown signature algorithms are rejected                         | `tests/basic.robot` |  
| Not‑authorized sender    | • Messages from unauthorized senders are rejected                                  | `tests/basic.robot` |  
| Header validation checks | • Generic validation of received header fields (including time‑window enforcement) | `tests/lwcmp.robot` |  
  ---    
### Certificate Request Validation (Section 4.1-4.1.4)

### Extensions Coverage

| Extension             | Validation Checks Covered                                                                                            | Body Types Covered | Test File           |
| --------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------------- |
| **BasicConstraints**  | CA certificate issuance allowed, invalid path length when `ca` is false, invalid `is_ca` with KeyUsage `keyCertSign` | `ir`               | `tests/basic.robot` |
| **KeyUsage**          | Certificates issued with `keyAgreement`/`digitalSignature` or `keyEncipherment`/`digitalSignature` usages            | `ir`               | `tests/basic.robot` |
| **ExtendedKeyUsage**  | Issuance with `cmcRA`, `cmcCA`, and `cmKGA` depending on policy                                                      | `ir`               | `tests/basic.robot` |
| **SubjectAltName**    | NULL-DN accepted with SAN, missing SAN rejected                                                                      | `ir`               | `tests/basic.robot` |
| **Invalid Extension** | Invalid extension rejected or accepted with `grantedWithMods`, depending on policy                                   | `ir`               | `tests/basic.robot` |

### Individual Test Cases – Section 4.1

| Test-case description                                                              | File                |     |  
| ---------------------------------------------------------------------------------- | ------------------- | --- |  
| CA MUST Reject IR Request With Untrusted Anchor                                    | `tests/lwcmp.robot` |     |  
| CA MUST Reject CR With Other PKI Management Entity Request                         | `tests/lwcmp.robot` |     |  
| CA MUST Reject Valid IR With Same Key                                              | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With BadPOP For Signature POPO                                   | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Missing POPO Structure For Key Allowed For Signing          | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Mismatched SignatureAlgorithm And PublicKey In CertTemplate | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Valid Proof-of-Possession And raVerified From EE            | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Invalid CertReqId                                           | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Missing Subject In CertTemplate                             | `tests/lwcmp.robot` |     |  
| CA MUST Issue A ECC Certificate With A Valid IR                                    | `tests/lwcmp.robot` |     |  
| CA MAY Issue A Ed25519 Certificate With A Valid IR                                 | `tests/lwcmp.robot` |     |  
| CA MAY Issue A Ed448 Certificate With A Valid IR                                   | `tests/lwcmp.robot` |     |  
| CA MAY Issue A RSA Certificate With A Valid IR                                     | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Invalid Algorithm                                           | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Too Short RSA Key In CertTemplate                           | `tests/lwcmp.robot` |     |  
| CA MUST Reject IR With Too Large RSA Key In CertTemplate                           | `tests/lwcmp.robot` |     |  
| CA MAY Issue A DSA Certificate                                                     | `tests/lwcmp.robot` |     |  
| CA or RA MUST Reject Not Authorized Sender                                         | `tests/basic.robot` |     |  
| CA MUST Either Reject Or Accept Valid KUR With Same Key                            | `tests/lwcmp.robot` |     |  

## Individual Test Cases

## Section 4.1

| Test Case                                                          | File                  |     |  
| ------------------------------------------------------------------ | --------------------- | --- |  
| CA MUST Accept EE Rejection Of The Issued Certificate              | cert_conf_tests.robot |     |  
| CA MUST Reject More Than One CertStatus Inside The certConf        | cert_conf_tests.robot |     |  
| CA MUST Reject `failInfo` With Status Accepted Inside The certConf | cert_conf_tests.robot |     |  
| CA MUST Accept certConf With A Different HashAlg And Version 3     | cert_conf_tests.robot |     |  
| CA MUST Reject certConf With A Different HashAlg But Version 2     | cert_conf_tests.robot |     |  
| CA MUST Reject certConf Signed With The Newly Issued Certificate   | cert_conf_tests.robot |     |  

## Section 4.1.1

| Test Case | File |
|-----------|------|
| CA MUST Accept Valid MAC-Protected Issuing Process | cert_conf_tests.robot |
| CA MUST Send A Valid IP After Receiving Valid IR | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid SIG-Protected IR | basic.robot |
| CA MUST Accept Certificate With NULL-DN And SAN | basic.robot |
| CA MUST Reject Certificate With NULL-DN And No SAN | basic.robot |
| CA MUST Reject Valid IR With Already Revoked Certificate | revocation_tests.robot |
| CA MUST Reject IR With More Than One CertReqMsg | lwcmp.robot |
| CA MUST Reject IR Request With Untrusted Anchor | lwcmp.robot |

## Section 4.1.2

| Test Case | File |
|-----------|------|
| CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected CR | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid SIG-Protected CR | basic.robot |
| CA MUST Reject CR From Other PKI Management Entity | lwcmp.robot |
| CA MUST Send A Valid CP After Receiving Valid CR | basic.robot |

## Section 4.1.3

| Test Case | File |
|-----------|------|
| CA MUST Reject A Valid MAC-Protected Key Update Request | basic.robot |
| CA MUST Send A Valid KUP After Receiving Valid KUR | basic.robot |
| CA MUST Accept ImplicitConfirm For KUR | basic.robot |
| CA MUST Correctly Support KUR Confirmation | basic.robot |
| CA MUST Reject Second KUR Request While First Is Unfinished | basic.robot |
| CA MUST Not Update Certificate Without Confirmation | basic.robot |
| CA MUST Not Allow New Request Without Confirmed Updated Certificate | basic.robot |
| CA SHOULD Not Allow New Request After Timeout If KUR Was Not Confirmed | basic.robot |
| CA SHOULD Not Allow RR For A Not Confirmed KUR | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid KUR | basic.robot |
| CA MUST Reject Valid KUR With Already Updated Certificate | basic.robot |
| CA MUST Reject Valid KUR With Already Revoked Certificate | revocation_tests.robot |
| CA MUST Reject IR With BadPOP For Signature POPO | lwcmp.robot |
| CA MUST Reject IR With Missing POPO Structure For Key Allowed For Signing | lwcmp.robot |
| CA MUST Reject IR With Mismatched SignatureAlgorithm And PublicKey | lwcmp.robot |
| CA MUST Reject IR With Valid POPO And `raVerified` Set | lwcmp.robot |
| CA MUST Reject IR With Invalid CertReqId | lwcmp.robot |
| CA MUST Reject IR With Missing Subject In CertTemplate | lwcmp.robot |
| CA MUST Issue A Valid ECC Certificate | lwcmp.robot |
| CA MAY Issue A Valid Ed25519 Certificate | lwcmp.robot |
| CA MAY Issue A Valid Ed448 Certificate | lwcmp.robot |
| CA MAY Issue A Valid RSA Certificate | lwcmp.robot |
| CA MUST Either Reject Or Accept Valid KUR With Same Key | lwcmp.robot |
| CA MUST Reject KUR With Incorrect Issuer In Control Structure | lwcmp.robot |
| CA MUST Reject KUR With Invalid SerialNumber In Control Structure | lwcmp.robot |
| CA MUST Reject Valid IR With Already Updated Certificate | lwcmp.robot |

## Section 4.1.4

| Test Case | File |
|-----------|------|
| CA MUST Issue A Certificate Upon Receiving A Valid P10CR | basic.robot |
| CA MUST Reject Request With Invalid CSR Signature | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected P10CR | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid SIG-Protected P10CR | basic.robot |
| CA MUST Issue Certificate Via P10CR Without ImplicitConfirm | lwcmp.robot |
| CA MUST Send A Valid CP After Receiving Valid P10CR | basic.robot |

### Section 4.1.5 MAC-Based Enrollment

> TODO should maybe be changed to do it for every PKIBody: `ir`, `cr`, `p10cr`.

| MAC Algorithm | Validation Checks      | Hash / Parameters                                                            | Body Types Covered | Specification Reference | Test File                            | Section Reference  |     |  
| ------------- | ---------------------- | ---------------------------------------------------------------------------- | ------------------ | ----------------------- | ------------------------------------ | ------------------ | --- |  
| **HMAC**      | Valid MAC, Invalid MAC | SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512 | `ir` (template)    | RFC 9481, RFC 9688      | `tests/mac_alg_pki_prot_tests.robot` | RFC 9481, RFC 9688 |     |  
| **KMAC**      | Valid MAC, Invalid MAC | SHAKE128, SHAKE256                                                           | `ir` (template)    | RFC 9688                | `tests/mac_alg_pki_prot_tests.robot` | RFC 9688           |     |  
| **AES-GMAC**  | Valid MAC, Invalid MAC | AES128-GMAC, AES192-GMAC, AES256-GMAC                                        | `ir` (template)    | RFC 9481                | `tests/mac_alg_pki_prot_tests.robot` | RFC 9481           |     |  
| **PBMAC1**    | Valid MAC, Invalid MAC | HMAC with SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-384, SHA3-512           | `ir` (template)    | RFC 9481, RFC 9688      | `tests/mac_alg_pki_prot_tests.robot` | RFC 9481, RFC 9688 |     |  
| **PBM**       | Valid MAC, Invalid MAC | HMAC with SHA1, SHA224, SHA256, SHA384, SHA512                               | `ir` (template)    | RFC 9481                | `tests/mac_alg_pki_prot_tests.robot` | RFC 9481           |     |  
  ---  

## Enrollment Scenarios

| Test Case                                                                                     | RFC 9483 Section | Test File             |  
|-----------------------------------------------------------------------------------------------|------------------|------------------------|  
| CA must issue certificate via P10cr **without** `implicitConfirm`                             | 4.1.4            | `tests/lwcmp.robot`    |  
| CA **MUST** support IR with `implicitConfirm` and PBMAC1 protection                           | 4.1.1            | `tests/lwcmp.robot`    |  
| CA **MUST** issue a valid certificate upon receiving a valid MAC-protected CR                 | 4.1.2            | `tests/basic.robot`    |  
| CA **MUST** reject a valid MAC-protected Key Update Request                                   | 4.1.3            | `tests/basic.robot`    |  
| CA **MUST** issue a valid certificate upon receiving a valid MAC-protected P10CR              | 4.1.4            | `tests/basic.robot`    |  

## Section 4.1.6

### Section 4.1.6.1 Key Transport (KTRI)

| Covered Scenario | Body Types Covered | Body Types Missing | File |
|------------------|--------------------|--------------------|------|
| Support for central key generation using Key Transport with IR and KUR | `ir`, `kur` | `cr`, `added_prot`, `batched` | kga.robot |
| Rejection of KGA requests without `keyEncipherment` in KeyUsage | `ir`, `kur` | `cr`, `added_prot`, `batched` | kga.robot |
| Acceptance of ML-DSA key transport request | `ir` | — | kga.robot |

| Test Case | File |
|-----------|------|
| CA MUST Support Key Transport Technique With IR | kga.robot |
| CA MUST Support Key Transport Technique With KUR | kga.robot |
| CA MUST Reject KGA Request For KTRI Without `keyEncipherment` Usage | kga.robot |
| CA MUST Accept A Valid KGA Request For ML-DSA | kga.robot |

### Section 4.1.6.2 Key Agreement (KARI)

| Covered Scenario | Body Types Covered | Body Types Missing | File |
|------------------|--------------------|--------------------|------|
| Support for central key generation using Key Agreement with IR and KUR | `ir`, `kur` | `cr`, `added_prot`, `batched` | kga.robot |
| Rejection of KGA request using KARI without `keyAgreement` in KeyUsage | `ir` | `kur`, `cr`, `added_prot`, `batched` | kga.robot |

| Test Case | File |
|-----------|------|
| CA MUST Support KeyAgreement Technique With IR | kga.robot |
| CA MUST Support KeyAgreement Technique With KUR | kga.robot |
| CA MUST Reject KGA IR Request For KARI Without `keyAgreement` Usage | kga.robot |

### Section 4.1.6.3 Password-Based Encryption (PWRI)

| Covered Scenario | Body Types Covered | Body Types Missing | File |
|------------------|--------------------|--------------------|------|
| Password-based encryption (PWRI) for centrally generated keys in IR | `ir` | `cr`, `added_prot` | kga.robot |
| Support for PWRI without algorithm parameters set | `ir` | `cr`, `added_prot` | kga.robot |
| Rejection of PWRI-based KUR request | `kur` | — | kga.robot |

| Test Case | File |
|-----------|------|
| CA MUST Support Password-Based KGA Technique With IR For ECC | kga.robot |
| CA MUST Support Password-Based KGA Without Algorithm Set | kga.robot |
| CA MUST Reject KUR KGA PWRI Message | kga.robot |

## Certificate Confirmation and PKI Confirmation Test Coverage

This document summarizes which test cases in the CMP test suite cover the handling of certificate confirmation (`certConf`) requests and PKI confirmation (`pkiconf`) responses according to [RFC 9483](https://datatracker.ietf.org/doc/html/rfc9483).
    
---    
## Certificate Confirmation Validation (RFC 9483 §4.1)

> Maybe add from each body, not only from ir.

| Check Area                       | Validation Checks Covered                      | Body Types *covered*           | Files                         |  
| -------------------------------- | ---------------------------------------------- | ------------------------------ | ----------------------------- |  
| With ImplicitConfirm             | `ir`, `cr`,`p10cr`, `kur`, `crr` (rejected),   | `krr`, `added_prot`, `batched` | `tests/basic.robot`           |  
| Without ImplicitConfirm          | `ir`, `cr`,`p10cr`, `kur`,                     | `krr`, `added_prot`, `batched` | `tests/basic.robot`           |  
| Multiple `CertStatus` entries    | Reject message with more than one entry        | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Invalid `certReqId`              | Reject negative / non-zero IDs                 | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Inconsistent `status`/`failInfo` | Reject `failInfo` when status is `accepted`    | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Hash algorithm mismatch          | Accept with `pvno` 3 / reject with `pvno` 2    | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Wrong signing certificate        | Reject message signed with issued certificate  | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Protection algorithm mix         | Reject PBM then PBMAC1 or missing protection   | `certConf`                     | `tests/cert_conf_tests.robot` |  
| `senderNonce` handling           | Reject missing or reused nonce                 | `certConf`                     | `tests/cert_conf_tests.robot` |  
| `recipNonce` handling            | Reject missing or mismatched nonce             | `certConf`                     | `tests/cert_conf_tests.robot` |  
| `transactionID` handling         | Reject omitted or altered ID                   | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Use of `implicitConfirm`         | MAY reject when present                        | `certConf`                     | `tests/cert_conf_tests.robot` |  
| Duplicate confirmation           | SHOULD respond with `certConfirmed` `failInfo` | `certConf`                     | `tests/cert_conf_tests.robot` |  
  ---    
## PKI Confirmation Response (RFC 9483 §3 & §4.1)

| Check Area                                              | Validation Checks Covered                                          | Body Types | Files                                            |  
| ------------------------------------------------------- | ------------------------------------------------------------------ | ---------- | ------------------------------------------------ |  
| Fresh `senderNonce`                                     | `pkiconf` must contain a new nonce                                 | `pkiconf`  | `tests/cert_conf_tests.robot`                    |  
| Matching MAC protection                                 | `pkiconf` uses the same MAC credentials as the initial request     | `pkiconf`  | `tests/cert_conf_tests.robot`                    |  
| Matching signature protection                           | `pkiconf` uses the same signing certificate as the initial request | `pkiconf`  | `tests/cert_conf_tests.robot`                    |  
| `pkiconf` returned for CR/KUR without `implicitConfirm` | Response after `cr`, `p10cr`, or `kur`                             | `pkiconf`  | `tests/basic.robot`, `tests/extra_issuing.robot` |  
| `pkiconf` protected with KEMBasedMAC                    | Response protected using KEMBasedMAC                               | `pkiconf`  | `tests_pq_and_hybrid/kem_tests.robot`            |  
  
---    
## Individual Test Cases

| Test Case Description                                                     | File                                                                                    |  
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |  
| CA MUST accept valid MAC-protected issuing process                        | `cert_conf_tests.robot`                                                                 |  
| CA MUST accept EE rejection of the issued certificate                     | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject more than one `CertStatus` inside the `certConf`           | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject invalid `certReqId` inside the `certConf`                  | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `failInfo` with status `accepted` inside the `certConf`    | `cert_conf_tests.robot`                                                                 |  
| CA MUST accept `certConf` with a different hash algorithm and `pvno = 3`  | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with a different hash algorithm but `pvno = 2`  | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` signed with the newly issued certificate        | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with first PKIMessage PBM-protected then PBMAC1 | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` without protection                              | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject IR with signature and then `certConf` MAC protection       | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with no `senderNonce`                           | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with reused `senderNonce`                       | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with no `recipNonce`                            | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with mismatched `recipNonce`                    | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with omitted `transactionID`                    | `cert_conf_tests.robot`                                                                 |  
| CA MUST reject `certConf` with altered `transactionID`                    | `cert_conf_tests.robot`                                                                 |  
| CA MAY reject `certConf` with `implicitConfirm`                           | `cert_conf_tests.robot`                                                                 |  
| CA SHOULD send `certConfirmed` when valid `certConf` is sent again        | `cert_conf_tests.robot`                                                                 |  
| CA `pkiconf` MUST respond with a fresh `senderNonce`                      | `cert_conf_tests.robot`                                                                 |  
| CA `pkiconf` MUST use MAC protection                                      | `cert_conf_tests.robot`                                                                 |  
| CA `pkiconf` MUST use the same signature protection                       | `cert_conf_tests.robot`                                                                 |  
| CA MUST correctly support KUR confirmation                                | `tests/basic.robot`                                                                     |  
| `pkiconf` returned for additional request flows (CR, P10CR, KEM)          | `tests/basic.robot`, `tests/extra_issuing.robot`, `tests_pq_and_hybrid/kem_tests.robot` |  
  ---    
## RFC 9483 Section 4.2 Revocation Coverage

Tests that exercise certificate **revocation** and **revival** behaviour are located in `revocation_tests.robot`.

**Revocation-Revive-request validation coverage**

| Check                   | Validation checks covered†                                                                       | Body types **covered**     | Body types missing  | Files                    |  
| ----------------------- | ------------------------------------------------------------------------------------------------ | -------------------------- | ------------------- | ------------------------ |  
| PKIMessage protection   | *MAC-based protection rejected*, *missing protection rejected*                                   | `rr`                       | added_prot, batched | `revocation_tests.robot` |  
| `sender`                | *sender must not equal issuer*, invalid sender                                                   | `rr`                       | added_prot, batched | `revocation_tests.robot` |  
| `CRLReason` `Extension` | *unknown value*, *multiple extensions*, *conflicting revoke/revive values*                       | `rr`                       | added_prot, batched | `revocation_tests.robot` |  
| `CertTemplate`          | *missing* `issuer` *or* `serialNumber`                                                           | `rr`                       | added_prot, batched | `revocation_tests.robot` |  
| `CertTemplate`          | *invalid issuer*, *invalid subject*, *mismatched publicKey*, *wrong version*, *invalid validity* | `rr`                       | added_prot, batched | `revocation_tests.robot` |  
| Extensions              | *invalid extension* or *mix of valid and invalid extensions*                                     | `rr`                       | added_prot, batched | `revocation_tests.robot` |  
| Valid revocation        | *accepted revocation request*, *`certRevoked` for duplicate*                                     | `rr` (also trusted Entity) | batched             | `revocation_tests.robot` |  
| valid revive            | *accepted revive request*, revive unkown,                                                        | `rr` (also trusted Entity) | batched, added_prot | `revocation_tests.robot` |  
| Revive request checks   | *invalid issuer*, *invalid subject*, *serialNumber not revoked*                                  | `rr`                       | batched, added_prot | `revocation_tests.robot` |  

#### Individual Test Cases Revocation

| Test-case description                                                                           | File                     |  
| ----------------------------------------------------------------------------------------------- | ------------------------ |  
| CA **MUST** Reject Revocation Request With **MAC-Based** Protection                             | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request **Without** Protection                                    | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Issuer** as Sender                                 | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With an **Unknown** `CRLReason` Value                     | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Multiple** `CRLReason` Extensions                  | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request Containing **Revoke** *and* **Revive** `CRLReason` Values | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Missing** `issuer`                                 | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Missing** `serialNumber`                           | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Invalid** `issuer`                                 | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Invalid** `subject`                                | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Mismatched** `publicKey` Inside `CertTemplate`     | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With a `version` **Other Than 2**                         | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Invalid** Extensions                               | `revocation_tests.robot` |  
| CA **MUST** Reject Revocation Request With **Mixed** Valid *and* Invalid Extensions             | `revocation_tests.robot` |  
| CA **MUST** Accept **Valid** Revocation Request                                                 | `revocation_tests.robot` |  
| CA **SHOULD** Respond With `certRevoked` for an **Already** Revoked Certificate                 | `revocation_tests.robot` |  
| CA **MUST** Reject **Revive** Request With **Invalid** `issuer`                                 | `revocation_tests.robot` |  
| CA **MUST** Reject **Revive** Request With **Invalid** `subject`                                | `revocation_tests.robot` |  
| CA **MUST** Reject **Revive** Request With **Non-Revoked** `serialNumber`                       | `revocation_tests.robot` |  
| CA **MUST** Accept **Valid** Revive Request                                                     | `revocation_tests.robot` |  
|                                                                                                 |                          |  
  ---    
## Coverage Section 4.3

Tests that exercise the support-message behavior defined in Section 4.3 are located in `support_messages.robot`.

| Section                                | Validation Checks Covered                                      | Body Type | Files                  |  
| -------------------------------------- | -------------------------------------------------------------- | --------- | ---------------------- |  
| **4.3.1** Get CA Certificates          | Valid retrieval and invalid `infoValue` handling               | `genm`    | support_messages.robot |  
| **4.3.2** Root CA Certificate Update   | Request with old root cert accepted; missing old cert rejected | `genm`    | support_messages.robot |  
| **4.3.3** Certificate Request Template | Template retrieval, optional profile, invalid `infoValue`      | `genm`    | support_messages.robot |  
| **4.3.4** Current CRL and CRL Updates  | Current CRL retrieval and CRL update retrieval                 | `genm`    | support_messages.robot |  

### Section 4.3.1

| Test Case                                                                  | File                   |  
| -------------------------------------------------------------------------- | ---------------------- |  
| CA MUST Reject Protected Genm With Get CA Certs                            | support_messages.robot |  
| CA MUST Respond To Protected Genm With Get CA Certs With Invalid InfoValue | support_messages.robot |  

### Section 4.3.2

| Test Case                                                                      | File                   |  
| ------------------------------------------------------------------------------ | ---------------------- |  
| CA MUST Respond To Protected Genm With Get Root CA Certificate Update          | support_messages.robot |  
| CA MUST Reject Protected Genm With Get Root CA Cert Update Without OldRootCert | support_messages.robot |  

### Section 4.3.3

| Test Case                                                                   | File                   |  
| --------------------------------------------------------------------------- | ---------------------- |  
| CA MUST Respond To Protected Genm With Get Certificate Request Template     | support_messages.robot |  
| CA MUST Accept Protected Genm With Get Cert Template With CertProfile Set   | support_messages.robot |  
| CA MUST Reject Protected Genm With Get Cert Template With Invalid InfoValue | support_messages.robot |  

### Section 4.3.4

| Test Case                                               | File                   |  
| ------------------------------------------------------- | ---------------------- |  
| CA MUST Respond To Valid Protected CurrentCRL Request   | support_messages.robot |  
| CA MUST Reject Invalid Value For CurrentCRL Request     | support_messages.robot |  
| CA MUST Respond To Valid Protected CRL Update Retrieval | support_messages.robot |  
  ---    
## Coverage Section 5.2

The tests that cover forwarding and modification of PKI messages described in Section 5.2 are located in `pki_mgmt_entity_op.robot`.

| Section                          | Validation checks covered                                                                                                                                                                                        | Body type         | File                       |  
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | -------------------------- |  
| **5.2.2.1 — Adding Protection**  | • Missing `senderNonce` or `transactionID` in nested messages<br>• Rejection of added MAC protection<br>• Correct response protection for MAC‑protected inner requests<br>• Acceptance of valid added protection | Nested `ir`       | `pki_mgmt_entity_op.robot` |  
| **5.2.2.2 — Batching Messages**  | • Valid nested batch processing<br>• Rejection of duplicate `transactionID` or `senderNonce`<br>• Validation of the protection of all inner messages                                                             | Nested batch `ir` | `pki_mgmt_entity_op.robot` |  
| **5.2.3.2 — Using `raVerified`** | • Acceptance of `ir` with `raVerified`<br>• Rejection of added protection or invalid protection<br>• Verification of `GeneralInfo` original message<br>• Rejection of `kur` with `raVerified`                    | `ir`, `kur`       | `pki_mgmt_entity_op.robot` |  

### 5.2.2.1 Adding Protection

| Test case                                                                      | File                       |  
| ------------------------------------------------------------------------------ | -------------------------- |  
| CA MUST reject added‑protection `PKIMessage` without copied `senderNonce`      | `pki_mgmt_entity_op.robot` |  
| CA MUST reject added‑protection `PKIMessage` without copied `transactionID`    | `pki_mgmt_entity_op.robot` |  
| CA MUST reject nested MAC‑protected `PKIMessage`                               | `pki_mgmt_entity_op.robot` |  
| CA MUST accept valid added protection for a `PKIMessage`                       | `pki_mgmt_entity_op.robot` |  
| CA MUST respond with MAC to added protection for a MAC‑protected inner request | `pki_mgmt_entity_op.robot` |  

### 5.2.2.2 Batching Messages

| Test case                                                             | File                       |  
| --------------------------------------------------------------------- | -------------------------- |  
| CA MUST accept a valid nested batch message                           | `pki_mgmt_entity_op.robot` |  
| CA MUST ensure each nested batch message has a unique `transactionID` | `pki_mgmt_entity_op.robot` |  
| CA MUST ensure each nested batch message has a unique `senderNonce`   | `pki_mgmt_entity_op.robot` |  
| CA MUST validate the protection of all inner messages                 | `pki_mgmt_entity_op.robot` |  

### 5.2.3.2 Using `raVerified`

| Test case                                                              | File                       |  
| ---------------------------------------------------------------------- | -------------------------- |  
| CA MUST accept `ir` from a trusted PKI with `raVerified`               | `pki_mgmt_entity_op.robot` |  
| CA MUST reject added‑protection `ir` from a trusted PKI with `raVerified` | `pki_mgmt_entity_op.robot` |  
| CA MUST confirm the original message inside `GeneralInfo`              | `pki_mgmt_entity_op.robot` |  
| CA MUST reject `kur` with `badPOP` from a trusted PKI with `raVerified` | `pki_mgmt_entity_op.robot` |  
| CA MUST reject `kur` with invalid protection from a trusted PKI        | `pki_mgmt_entity_op.robot` |
