# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
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
Library             ../pq_logic/pq_validation_utils.py


#Suite Setup         Do PQ SIG Tests
Test Tags           pqc  hybrid-sig

*** Variables ***

# New Tags: composite-sig, multiple-auth

#${uri_multiple_auth}=   https://localhost:8080/cmp/cert-bindings-for-multiple-authentication
${uri_multiple_auth}=   ${None}
${uri_multiple_auth_neg}=  ${None}
${DEFAULT_ML_DSA_ALG}=   ml-dsa-87
${Allowed_freshness}=   500

*** Test Cases ***

############################
# Composite Signature Tests
############################

# Technically not all parts have to be defined, because a correct combination is
# built, but for better readability included.

#### Composite Signature Positive Tests ####

# Normally, you would use `ir` as usual; this is just to demonstrate that csr can be used in almost the same way.

CA MUST Issue A Valid Composite RSA-PSS Certificate From CSR
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid CSR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    signing_key=${key}    common_name=${cm}   use_rsa_pss=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    Validate Migration Certificate Key Usage   ${cert}

CA MUST Issue a Valid Composite-Sig RSA Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=   Build Ir From Key    ${key}   common_name=${cm}  recipient=${RECIPIENT}  omit_fields=senderKID,sender   implicit_confirm=${True}
    ${response}=       Exchange PKIMessage    ${ir}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the secp256r1 curve
    ...                and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ec
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite EC-brainpool Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the brainpoolP256r1
    ...                curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED25519 Certificate
    [Documentation]   Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...               composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65 as pq
    ...               algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]            composite-sig   positive   ed25519
    ${key}=           Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=            Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED448 Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed448
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_csr}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_csr}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

############################
## Pre-Hashed Versions
############################

CA MUST Issue A Valid Composite RSA-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as
    ...                pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True  use_rsa_pss=False
    ${ir}=          Build Ir From Key    ${key  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite RSA-PSS-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44
    ...                as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa-pss  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True   use_rsa_pss=True
    ${ir}=          Build Ir From Key    ${key  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is EC key on the secp256r1
    ...                curve and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC-brainpool-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is EC key on the
    ...                brainpoolP256r1 curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request
    ...                and issue a valid certificate.
    [Tags]             composite-sig   positive   ec  prehashed  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite ED25519-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65
    ...                as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed25519   prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite ED448-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as
    ...                pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed448  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted


#### Composite Signature Negative Tests ####

CA MUST Reject An Invalid POP For Composite RSA
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA, and the pq algorithm
    ...                used is ML-DSA-44. The CA must detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True

CA MUST Reject An Invalid POP For Composite RSA-PSS
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA-PSS, and the pq algorithm
    ...                used is ML-DSA-44. The CA must detect the invalid POP and reject the re quest. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True

CA MUST Reject An Invalid POP For Composite EC
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a invalid POP for 
    ...                a composite signature algorithm. The traditional algorithm used is EC key on the secp256r1 curve
    ...                and ML-DSA-44 as pq algorithm. The CA must detect the invalid POP and reject the request. The CA
    ...                MAY respond with the optional failInfo `badPOP`.
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True
