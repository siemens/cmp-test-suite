# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py

Suite Setup         Set Up Hybrid Sig Suite
Test Tags           pqc  hybrid-sig


*** Test Cases ***
############################
# Composite Signature Tests
############################

# Technically not all parts have to be defined, because a correct combination is
# built, but for better readability included.

#### Composite Signature Positive Tests ####

# Normally, you would use `ir` as usual; this is just to demonstrate that csr can be used in almost the same way.

CA MUST Issue A Valid Composite RSA-PSS Certificate From CSR
    [Documentation]    Verifies compliance with Composite Sig Draft 06 by sending a valid CSR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa-pss   pre_hash
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    ${key}    common_name=${cm}   use_rsa_pss=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}
    ...                exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}

CA MUST Issue a Valid Composite-Sig RSA Certificate
    [Documentation]    Verifies compliance with omposite Sig Draft 06 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa   pre_hash
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=   Build Ir From Key    ${key}   ${cm}  recipient=${RECIPIENT}  exclude_fields=senderKID,sender
    ...      implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage   ${ir}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft 06 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the secp256r1 curve
    ...                and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec   pre_hash
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite EC-brainpool Certificate
    [Documentation]    Verifies compliance with omposite Sig Draft 06 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the brainpoolP256r1
    ...                curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec  brainpool   pre_hash
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa
    ...                curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED25519 Certificate
    [Documentation]   Verifies compliance with omposite Sig Draft 06 by sending a valid IR with a POP for the
    ...               composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65 as pq
    ...               algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]            composite-sig   positive   ed25519   pre_hash
    ${key}=           Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=            Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED448 Certificate
    [Documentation]    Verifies compliance with omposite Sig Draft 06 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed448   pre_hash
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

#### Composite Signature Mixed/Security Tests ####

CA MUST Reject Composite RSA with invalid RSA key length
    [Documentation]    As defined in omposite Sig Draft 06, we send a valid IR with a POP for composite signature.
    ...                The traditional algorithm is RSA key with an invalid length (512-bits) and ML-DSA-44 as pq
    ...                algorithm. The CA MUST reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             composite-sig   negative  rsa
    # generates a rsa key with length 512 bits.
    ${trad_key}=   Generate Key       algorithm=bad_rsa_key
    ${pq_key}=     Generate Key       algorithm=ml-dsa-44
    ${key}=            Generate Key    algorithm=composite-sig   trad_key=${trad_key}   pq_key=${pq_key}
    ${cm}=             Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo   ${key}
    ${ir}=    Build Ir From Key    ${key}  ${cm}
    ...         spki=${spki}  recipient=${RECIPIENT}  exclude_fields=sender,senderKID
    ${protected_ir}=  Default Protect PKIMessage   ${ir}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badDataFormat

#### Security Related #####

CA MUST Reject Composite Sig with Traditional Revoked key Due Compromise
    [Documentation]    As defined in omposite Sig Draft 06 Section 11.2, we generate a CSR with a composite
    ...                signature. The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq
    ...                algorithm. The CA MUST reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate`.
    [Tags]             composite-sig   negative  security   revocation
    ${revoked_cert}  ${revoked_key}=   Issue And Revoke A Fresh Cert    reason=keyCompromise
    ${cm}=             Get Next Common Name
    ${key}=            Generate Key    algorithm=composite-sig  trad_key=${revoked_key}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${revoked_key}
    ...                cert=${revoked_cert}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA MUST Reject Issuing Already in use Traditional Key
    [Documentation]    As defined in omposite Sig Draft 06 Section 11.3, we generate a valid IR with a composite
    ...                signature algorithm. The traditional algorithm is already in use and a matching ML-DSA key is
    ...                generated. The CA MUST reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             composite-sig   negative  security
    ${key}=            Generate Key    algorithm=composite-sig  trad_key=${ISSUED_KEY}
    ${cert_template}=   Prepare CertTemplate    ${key}   cert=${ISSUED_CERT}   include_fields=publicKey,subject
    ${ir}=    Build Ir From Key    ${key}   cert_template=${cert_template}
    ...       recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest


*** Keywords ***
Set Up Hybrid Sig Suite
    [Documentation]    Initializes the test suite for hybrid/composite signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                composite issuing endpoint for certificate requests using hybrid signature algorithms
    ...                (combinations of PQ and traditional algorithms).
    ...
    ...                The CA_CMP_URL suite variable is updated to the composite-specific endpoint.
    Set Up Test Suite
    ${url}=   Get Composite Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE
