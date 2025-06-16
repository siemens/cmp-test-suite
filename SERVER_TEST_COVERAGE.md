
# Test Coverage Server
## RFC 9483 LwCMP

### PKIHeader Section 3.1

| Header field                | Validation checks covered                                                                | Body types **covered**                                                       | Body types **missing**                  | Files                                     |
| --------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------- | ----------------------------------------- |
| **pvno**                    | invalid value (≠ 2 or 3)                                                                 | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, added_protection, `batch`   | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **sender**                  | invalid type (not`directoryName` MAC) , set to issuer (SIG), invalid subject (SIG)       | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **senderKID**               | missing (MAC & SIG), invalid (MAC & SIG)                                                 | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **messageTime**             | missing, outside allowed window, too old                                                 | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **protectionAlg** (MAC/SIG) | MAC-alg mismatch, SIG-alg mismatch, inkonsistent (MAC & SIG)                             | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **senderNonce**             | missing, too short (< 16 B), too long (> 16 B)                                           | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **recipNonce**              | present, matching to senderNonce                                                         | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **implicitConfirm**         | `present and used`, `invalid value`, clashes with `confirmWaitTime`, present not allowed | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **confirmWaitTime**         | UTCTime used, clashes with `implicitConfirm`                                             | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| **Full PKIHeader**          | valid header for negative and positive cases                                             | `ir`, `cr`, `kur`, `p10cr`, `ccr`, `rr`, `genm`, `added_protection`, `batch` | —                                       | verbose_gen_msg_checks.robot, lwcmp.robot |
| senderNonce, recipNonce     | matching senderNonce / recipNonce                                                        | `certConf`,`pkiconf`                                                         | added_prot_cert_conf, batched_cert_conf | cert_conf_test.robot                      |


# Test Coverage Server RFC 9483 LwCMP

### Certificate Request Validation (Section 4.1-4.1.4)

| Check Area                      | Validation Checks Covered                                                           | Body Types Covered            | Body Types Missing                                      | Test Files                                             |
| ------------------------------- | ----------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------- | ------------------------------------------------------ |
| **Signature-based POPO**        | Invalid signature, missing `POPO`, mismatched algorithm/key, incorrect `raVerified` | `ir`                          | `cr`, `kur`, `p10cr` (note: not complete for all types) | `tests/lwcmp.robot`, `tests/basic.robot`               |
| **Not Authorized Sender**       | Unauthorized sender rejected                                                        | `ir`                          | (To be decided)                                         | `tests/basic.robot`                                    |
| **Device Certificate (LDevID)** | Request signed by a certificate from a different PKI (`cr` rejected, `ir` accepted) | `cr`, `ir`                    | `kur`, `added_prot`, `batched`                          | `tests/lwcmp.robot`                                    |
| **Same Key Reuse**              | Repeat request with already certified key rejected (IR and KUR)                     | `ir`, `kur`                   | `cr`, `p10cr`, `batched`, `added_prot`                  | `tests/lwcmp.robot`                                    |
| **CertReqId**                   | Invalid `certReqId`                                                                 | `ir`                          | `cr`, `kur`, `p10cr`, `batched`, `added_prot`           | `tests/lwcmp.robot`                                    |
| **Missing Subject and SAN**     | Both missing, only SAN present, both present                                        | `ir`, `ccr`                   | `cr`, `kur`, `p10cr`, `batched`, `added_prot`           | `tests/basic.robot`, `tests/cross_certification.robot` |
| **CertTemplate Validity**       | Missing (`crr`), present, in the past, overly long validity period                  | `ir`                          | `cr`, `ccr`, `kur`, `p10cr`, `batched`, `added_prot`    | `tests/basic.robot`, `tests/cross_certification.robot` |
| **KUR Controls**                | Wrong issuer or serial in KUR                                                       | `kur`                         | `batched`, `added_prot`                                 | `tests/lwcmp.robot`                                    |
| Valid PKIBody returned          | positive                                                                            | `ir` `p10cr` `cr` `kur` `ccr` | `batched`, `added_prot`                                 | `tests/basic.robot`, `tests/cross_certification.robot` |

### Extensions Coverage

| Extension             | Validation Checks Covered                                                                                            | Body Types Covered | Test File           |
| --------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------------- |
| **BasicConstraints**  | CA certificate issuance allowed, invalid path length when `ca` is false, invalid `is_ca` with KeyUsage `keyCertSign` | `ir`               | `tests/basic.robot` |
| **KeyUsage**          | Certificates issued with `keyAgreement`/`digitalSignature` or `keyEncipherment`/`digitalSignature` usages            | `ir`               | `tests/basic.robot` |
| **ExtendedKeyUsage**  | Issuance with `cmcRA`, `cmcCA`, and `cmKGA` depending on policy                                                      | `ir`               | `tests/basic.robot` |
| **SubjectAltName**    | NULL-DN accepted with SAN, missing SAN rejected                                                                      | `ir`               | `tests/basic.robot` |
| **Invalid Extension** | Invalid extension rejected or accepted with `grantedWithMods`, depending on policy                                   | `ir`               | `tests/basic.robot` |

### Individual Test Cases – Section 4.1

| Test-case description                                                            | File               |
|----------------------------------------------------------------------------------|--------------------|
| CA MUST Reject IR Request With Untrusted Anchor                                 | `tests/lwcmp.robot` |
| CA MUST Reject CR With Other PKI Management Entity Request                      | `tests/lwcmp.robot` |
| CA MUST Reject Valid IR With Same Key                                           | `tests/lwcmp.robot` |
| CA MUST Reject IR With BadPOP For Signature POPO                                | `tests/lwcmp.robot` |
| CA MUST Reject IR With Missing POPO Structure For Key Allowed For Signing       | `tests/lwcmp.robot` |
| CA MUST Reject IR With Mismatched SignatureAlgorithm And PublicKey In CertTemplate | `tests/lwcmp.robot` |
| CA MUST Reject IR With Valid Proof-of-Possession And raVerified From EE         | `tests/lwcmp.robot` |
| CA MUST Reject IR With Invalid CertReqId                                        | `tests/lwcmp.robot` |
| CA MUST Reject IR With Missing Subject In CertTemplate                          | `tests/lwcmp.robot` |
| CA MUST Issue A ECC Certificate With A Valid IR                                 | `tests/lwcmp.robot` |
| CA MAY Issue A Ed25519 Certificate With A Valid IR                              | `tests/lwcmp.robot` |
| CA MAY Issue A Ed448 Certificate With A Valid IR                                | `tests/lwcmp.robot` |
| CA MAY Issue A RSA Certificate With A Valid IR                                  | `tests/lwcmp.robot` |
| CA MUST Reject IR With Invalid Algorithm                                        | `tests/lwcmp.robot` |
| CA MUST Reject IR With Too Short RSA Key In CertTemplate                        | `tests/lwcmp.robot` |
| CA MUST Reject IR With Too Large RSA Key In CertTemplate                        | `tests/lwcmp.robot` |
| CA MAY Issue A DSA Certificate                                                  | `tests/lwcmp.robot` |
| CA or RA MUST Reject Not Authorized Sender                                      | `tests/basic.robot` |
| CA MUST Either Reject Or Accept Valid KUR With Same Key                         | `tests/lwcmp.robot` |

## Individual Test Cases


## Section 4.1

| Test Case                                                                               | File                  |
| --------------------------------------------------------------------------------------- | --------------------- |
| CA MUST Accept EE Rejection Of The Issued Certificate                                   | cert_conf_tests.robot |
| CA MUST Reject More Than One CertStatus Inside The certConf                             | cert_conf_tests.robot |
| CA MUST Reject `failInfo` With Status Accepted Inside The certConf                      | cert_conf_tests.robot |
| CA MUST Accept certConf With A Different HashAlg And Version 3                          | cert_conf_tests.robot |
| CA MUST Reject certConf With A Different HashAlg But Version 2                          | cert_conf_tests.robot |
| CA MUST Reject certConf Signed With The Newly Issued Certificate                        | cert_conf_tests.robot |

## Section 4.1.1

| Test Case                                                                 | File                   |
| ------------------------------------------------------------------------- | ---------------------- |
| CA MUST Accept Valid MAC-Protected Issuing Process                        | cert_conf_tests.robot  |
| CA MUST Send A Valid IP After Receiving Valid IR                          | basic.robot            |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid SIG-Protected IR | basic.robot            |
| CA MUST Accept Certificate With NULL-DN And SAN                           | basic.robot            |
| CA MUST Reject Certificate With NULL-DN And No SAN                        | basic.robot            |
| CA MUST Reject Valid IR With Already Revoked Certificate                  | revocation_tests.robot |
| CA MUST Reject IR With More Than One CertReqMsg                           | lwcmp.robot            |
| CA MUST Reject IR Request With Untrusted Anchor                           | lwcmp.robot            |

## Section 4.1.2

| Test Case                                                                 | File        |
| ------------------------------------------------------------------------- | ----------- |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected CR | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid SIG-Protected CR | basic.robot |
| CA MUST Reject CR From Other PKI Management Entity                        | lwcmp.robot |
| CA MUST Send A Valid CP After Receiving Valid CR                          | basic.robot |

## Section 4.1.3

| Test Case                                                                             | File                   |
| ------------------------------------------------------------------------------------- | ---------------------- |
| CA MUST Reject A Valid MAC-Protected Key Update Request                               | basic.robot            |
| CA MUST Send A Valid KUP After Receiving Valid KUR                                    | basic.robot            |
| CA MUST Accept ImplicitConfirm For KUR                                                | basic.robot            |
| CA MUST Correctly Support KUR Confirmation                                            | basic.robot            |
| CA MUST Reject Second KUR Request While First Is Unfinished                           | basic.robot            |
| CA MUST Not Update Certificate Without Confirmation                                   | basic.robot            |
| CA MUST Not Allow New Request Without Confirmed Updated Certificate                   | basic.robot            |
| CA SHOULD Not Allow New Request After Timeout If KUR Was Not Confirmed                | basic.robot            |
| CA SHOULD Not Allow RR For A Not Confirmed KUR                                        | basic.robot            |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid KUR                          | basic.robot            |
| CA MUST Reject Valid KUR With Already Updated Certificate                             | basic.robot            |
| CA MUST Reject Valid KUR With Already Revoked Certificate                             | revocation_tests.robot |
| CA MUST Reject IR With BadPOP For Signature POPO                                      | lwcmp.robot            |
| CA MUST Reject IR With Missing POPO Structure For Key Allowed For Signing             | lwcmp.robot            |
| CA MUST Reject IR With Mismatched SignatureAlgorithm And PublicKey                    | lwcmp.robot            |
| CA MUST Reject IR With Valid POPO And `raVerified` Set                                | lwcmp.robot            |
| CA MUST Reject IR With Invalid CertReqId                                              | lwcmp.robot            |
| CA MUST Reject IR With Missing Subject In CertTemplate                                | lwcmp.robot            |
| CA MUST Issue A Valid ECC Certificate                                                 | lwcmp.robot            |
| CA MAY Issue A Valid Ed25519 Certificate                                              | lwcmp.robot            |
| CA MAY Issue A Valid Ed448 Certificate                                                | lwcmp.robot            |
| CA MAY Issue A Valid RSA Certificate                                                  | lwcmp.robot            |
| CA MUST Either Reject Or Accept Valid KUR With Same Key                               | lwcmp.robot            |
| CA MUST Reject KUR With Incorrect Issuer In Control Structure                         | lwcmp.robot            |
| CA MUST Reject KUR With Invalid SerialNumber In Control Structure                     | lwcmp.robot            |
| CA MUST Reject Valid IR With Already Updated Certificate                              | lwcmp.robot            |

## Section 4.1.4

| Test Case                                                                    | File        |
| ---------------------------------------------------------------------------- | ----------- |
| CA MUST Issue A Certificate Upon Receiving A Valid P10CR                     | basic.robot |
| CA MUST Reject Request With Invalid CSR Signature                            | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid MAC-Protected P10CR | basic.robot |
| CA MUST Issue A Valid Certificate Upon Receiving A Valid SIG-Protected P10CR | basic.robot |
| CA MUST Issue Certificate Via P10CR Without ImplicitConfirm                  | lwcmp.robot |
| CA MUST Send A Valid CP After Receiving Valid P10CR                          | basic.robot |

### Section 4.1.5 MAC PKIProtection

> **Note**: Those test cases were created by a Python script at `./script/generate_pki_prot_tests.py`.

| Key Algorithm (PKIProtection) | Validation Checks Covered                        | Hash Algorithms                                                                            | Body Types **Covered** | Reference          | Files                                 | Section Reference  |
| ----------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------ | ---------------------- | ------------------ | ------------------------------------- | ------------------ |
| **Ed25519**                   | Valid signature, Invalid signature               | (implicit in Ed25519)                                                                      | `ir` (template)        | RFC 9481           | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481           |
| **Ed448**                     | Valid signature, Invalid signature               | (implicit in Ed448)                                                                        | `ir` (template)        | RFC 9481           | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481           |
| **RSA**                       | Valid signature, Invalid signature, BadAlg(SHA1) | SHA1[^1], SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512           | `ir` (template)        | RFC 9481, RFC 9688 | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481, RFC 9688 |
| **RSA-PSS**                   | Valid signature, Invalid signature               | SHA256, SHAKE128, SHAKE256                                                                 | `ir` (template)        | RFC 9481           | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481           |
| **ECDSA**                     | Valid signature, Invalid signature,              | SHA224, SHA256, SHA384, SHA512, SHAKE128, SHAKE256, SHA3-224, SHA3-256, SHA3-384, SHA3-512 | `ir` (template)        | RFC 9481, RFC 9688 | `tests/trad_alg_pki_prot_tests.robot` | RFC 9481, RFC 9688 |

[^1]: SHA1 is considered weak and is marked as `BadAlg(SHA1)` due to known cryptographic vulnerabilities.

## Section 4.1.6

### Section 4.1.6.1

> Note: Could/Should be added with a python script for all supported key types and combinations.

| What is Covered                                                        | Body types *covered* | Body types *missing*         | File      |
| ---------------------------------------------------------------------- | -------------------- | ---------------------------- | --------- |
| Support for central key generation using Key Transport with IR and KUR | `ir`, `kur`          | `cr`, `added_prot` `batched` | kga.robot |
| Rejection of KGA requests without `keyEncipherment` in keyUsage        | `ir`, `kur`          | `cr`, `added_prot` `batched` | kga.robot |
| Acceptance of ML-DSA key transport request                             | `ir`                 |                              | kga.robot |

| Test Case                                                           | File      |
| ------------------------------------------------------------------- | --------- |
| CA MUST Support Key Transport Technique With IR                     | kga.robot |
| CA MUST Support Key Transport Technique With KUR                    | kga.robot |
| CA MUST Reject KGA Request For KTRI Without `keyEncipherment` Usage | kga.robot |
| CA MUST Accept A Valid KGA Request For ML-DSA                       | kga.robot |

### Section 4.1.6.2

> Note: Could/Should be added with a python script for all supported key types and combinations.

| What is Covered                                                        | Body types _covered_ | Body types _missing_                | File      |
| ---------------------------------------------------------------------- | -------------------- | ----------------------------------- | --------- |
| Support for central key generation using Key Agreement with IR and KUR | `ir`, `kur`          | `cr`, `added_prot`, `batched`       | kga.robot |
| Rejection of KGA request using KARI without `keyAgreement` in keyUsage | `ir`                 | `kur`, `cr`, `added_prot` `batched` | kga.robot |

| Test Case                                                           | File      |
| ------------------------------------------------------------------- | --------- |
| CA MUST Support KeyAgreement Technique With IR                      | kga.robot |
| CA MUST Support KeyAgreement Technique With KUR                     | kga.robot |
| CA MUST Reject KGA IR Request For KARI Without `keyAgreement` Usage | kga.robot |

### Section 4.1.6.3

> Maybe add `kur`.

| What is Covered                                                     | Body types *covered* | Body types *missing* | File      |
| ------------------------------------------------------------------- | -------------------- | -------------------- | --------- |
| Password-based encryption (PWRI) for centrally generated keys in IR | `ir`                 | `cr`, `added_prot`   | kga.robot |
| Support for PWRI without algorithm parameters set                   | `ir`                 | `cr`, `added_prot`   | kga.robot |
| Rejection of PWRI-based KUR request                                 | `kur`                |                      | kga.robot |

| Test Case                                                    | File      |
| ------------------------------------------------------------ | --------- |
| CA MUST Support Password-Based KGA Technique With IR For ECC | kga.robot |
| CA MUST Support Password-Based KGA Without Algorithm Set     | kga.robot |
| CA MUST Reject KUR KGA PWRI Message                          | kga.robot |

## RFC 9483 Section 4.2 Revocation Coverage

Tests that exercise certificate **revocation** and **revival** behaviour are located in `revocation_tests.robot`.

**Revocation-Revive-request validation coverage**

| Check                   | Validation checks covered†                                                                       | Body types **covered**    | Body types missing  | Files                    |
| ----------------------- | ------------------------------------------------------------------------------------------------ | ------------------------- | ------------------- | ------------------------ |
| PKIMessage protection   | *MAC-based protection rejected*, *missing protection rejected*                                   | `rr`                      | added_prot, batched | `revocation_tests.robot` |
| `sender`                | *sender must not equal issuer*, invalid sender                                                   | `rr`                      | added_prot, batched | `revocation_tests.robot` |
| `CRLReason` `Extension` | *unknown value*, *multiple extensions*, *conflicting revoke/revive values*                       | `rr`                      | added_prot, batched | `revocation_tests.robot` |
| `CertTemplate`          | *missing* `issuer` *or* `serialNumber`                                                           | `rr`                      | added_prot, batched | `revocation_tests.robot` |
| `CertTemplate`          | *invalid issuer*, *invalid subject*, *mismatched publicKey*, *wrong version*, *invalid validity* | `rr`                      | added_prot, batched | `revocation_tests.robot` |
| Extensions              | *invalid extension* or *mix of valid and invalid extensions*                                     | `rr`                      | added_prot, batched | `revocation_tests.robot` |
| Valid revocation        | *accepted revocation request*, *`certRevoked` for duplicate*                                     | `rr` (also trusted Enity) | batched             | `revocation_tests.robot` |
| valid revive            | *accepted revive request*, revive unkown,                                                        | `rr` (also trusted Enity) | batched, added_prot | `revocation_tests.robot` |
| Revive request checks   | *invalid issuer*, *invalid subject*, *serialNumber not revoked*                                  | `rr`                      | batched, added_prot | `revocation_tests.robot` |

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

Tests that exercise the support-message behavior defined in Section 4.3 are located in `support_messages.robot`.

| Section                                | Validation Checks Covered                                      | Body Type | Files                  |
| -------------------------------------- | -------------------------------------------------------------- | --------- | ---------------------- |
| **4.3.1** Get CA Certificates          | Valid retrieval and invalid `infoValue` handling               | `genm`    | support_messages.robot |
| **4.3.2** Root CA Certificate Update   | Request with old root cert accepted; missing old cert rejected | `genm`    | support_messages.robot |
| **4.3.3** Certificate Request Template | Template retrieval, optional profile, invalid `infoValue`      | `genm`    | support_messages.robot |
| **4.3.4** Current CRL and CRL Updates  | Current CRL retrieval and CRL update retrieval                 | `genm`    | support_messages.robot |


### Section 4.3.1

|Test Case|File|
|---|---|
|CA MUST Reject Protected Genm With Get CA Certs|support_messages.robot|
|CA MUST Respond To Protected Genm With Get CA Certs With Invalid InfoValue|support_messages.robot|
### Section 4.3.2

| Test Case                                                                      | File                   |
| ------------------------------------------------------------------------------ | ---------------------- |
| CA MUST Respond To Protected Genm With Get Root CA Certificate Update          | support_messages.robot |
| CA MUST Reject Protected Genm With Get Root CA Cert Update Without OldRootCert | support_messages.robot |
### Section 4.3.3

|Test Case|File|
|---|---|
|CA MUST Respond To Protected Genm With Get Certificate Request Template|support_messages.robot|
|CA MUST Accept Protected Genm With Get Cert Template With CertProfile Set|support_messages.robot|
|CA MUST Reject Protected Genm With Get Cert Template With Invalid InfoValue|support_messages.robot|
### Section 4.3.4

| Test Case                                               | File                   |
| ------------------------------------------------------- | ---------------------- |
| CA MUST Respond To Valid Protected CurrentCRL Request   | support_messages.robot |
| CA MUST Reject Invalid Value For CurrentCRL Request     | support_messages.robot |
| CA MUST Respond To Valid Protected CRL Update Retrieval | support_messages.robot |

---
