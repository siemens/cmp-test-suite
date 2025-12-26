# Copyright 2024 Siemens AG # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
#

*** Settings ***
Documentation     An example resource file with configuration options that are meant for use on your local development
...               system. Use this file as a template when adapting the tests to a specific environment.


*** Variables ***
# the dev-environment always runs the latest version
# qa - the stable version
${PORT}    5000
${CA_BASE_URL}   http://127.0.0.1:${PORT}/
${CA_CMP_URL}    http://127.0.0.1:${PORT}/issuing
# the other URL is are down below.
#${CA_CMP_URL}    https://broker.sdo-dev.siemens.cloud/.well-known/cmp

# The initial issued certificate and key for running the tests.
${ISSUED_KEY}    ${None}
${ISSUED_CERT}   ${None}
${INIT_SUFFIX}   issuing
# The initial issued certificate and key for running the tests setup.
${INITIAL_KEY_PATH}    ${None}
${INITIAL_CERT_PATH}   ${None}
${INITIAL_KEY_PASSWORD}   ${None}

${PRESHARED_SECRET}    SiemensIT
${SENDER}              CN=CloudCA-Integration-Test-User
${RECIPIENT}           CN=CloudPKI-Integration-Test
${DEFAULT_X509NAME}    CN=CloudCA-Integration-Test-User
# either signature or an MAC algorithm.
${DEFAULT_PROTECTION}   signature

# Test the LWCMP version.
${LWCMP}   ${True}
# Whether to enforce the algorithm to be set in the
# Algorithm Profile RFC9481.
# Does not affect the PQ signature algorithms.
# Only MAC and traditional signatures.
${ENFORCE_RFC9481}   ${False}

##### About Issuing:

# Implicit confirmation allowed.
${ALLOW_IMPLICIT_CONFIRM}  ${True}

# then send always the ${DEFAULT_X509NAME} inside the `CertTemplate` and csr
${ALLOW_ONLY_ONE_SENDER}   ${True}
# for test cases are only the same keys can be used to save resources.
# TODO implement have a list maybe called burned_keys and send each time a new one.
${ALLOW_IR_SAME_KEY}       ${False}
# Could be used to always load the same PKIMessage structure and patch it during testing.
# TODO implement a one dataclass for the PKIMessage to always patch the same message if allowed,
# to have some lax test settings and save as much resources as possible.
${IRELEVANT_messageTime}    ${FALSE}
# Currently does not support strict validation on it.
# MUST be used but if not a strict setting could be ignored.
${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}   ${True}

##### Security
# If only enc keys are allowed:
# and the Cert is not directly encrypted by a global key
# for testing purposes.
${ENC_CERT_PASSWORD}    ${NONE}
# For key-transport RSA key or ECC public key for the key-agreement,
# Currently is the logic not supported!
${ENC_CERT_EE_KEY}      ${NONE}

# Examples to check that a Unique Symmetric KEK was used!
${EXAMPLES_KUR_GEN}    10
${GATHER_NONCES_FROM_MSG_BODIES}    ip,cp,kup,rp,error
${ALLOW_MAC_PROTECTION}   ${True}
# decides whether to use rfc822Name or the directoryName with the common name set.
# MUST be set in a strict setting.

# If True must be the same MAC algorithm. In the future also supports
# TO enforce directoryName choice for the sender field, if supported.
${STRICT_MAC_VALIDATION}   ${True}

${EXTENDED_KEY_USAGE_STRICTNESS}   LAX
# As defined by Rfc9383 Section 1.2
${KEY_USAGE_STRICTNESS}   LAX
# Configuration for strict mode.
${STRICT}   ${True}

# IF legacy systems are used, it might be allowed to use,
# to use NULL instead of absent AlgorithmIdentifier `parameters`
${ALLOW_NULL_INSTEAD_OF_ABSENT}   ${False}

##### About Algorithms
${DEFAULT_KEY_LENGTH}    2048
${DEFAULT_ALGORITHM}    rsa
${DEFAULT_ECC_CURVE}   secp256r1
${DEFAULT_MAC_ALGORITHM}   password_based_mac
${DEFAULT_KGA_ALGORITHM}   rsa
${DEFAULT_PQ_SIG_ALGORITHM}   ml-dsa-44
${DEFAULT_PQ_KEM_ALGORITHM}   ml-kem-512
${DEFAULT_KEY_AGREEMENT_ALG}   x25519
${DEFAULT_KEY_ENCIPHERMENT_ALG}   ml-kem-768
${DEFAULT_ML_DSA_ALG}    ml-dsa-87
${DEFAULT_ML_KEM_ALG}    ml-kem-768

##### Extra Issuing Logic
${CA_RSA_ENCR_CERT}    data/unittest/ca_encr_cert_rsa.pem
${CA_X25519_CERT}   data/unittest/ca_encr_cert_x25519.pem
${CA_X448_CERT}     data/unittest/ca_encr_cert_x448.pem
${CA_ECC_CERT}      data/unittest/ca_encr_cert_ecc.pem
${CA_HYBRID_KEM_CERT}   data/unittest/ca_encr_cert_xwing.pem
${CA_KEM_CERT}     data/unittest/ca_encr_cert_ml_kem_768.pem

##### About CertTemplate
${ALLOWED_ALGORITHM}   ed25519,rsa,ecc,ed448,x25519,x448,dsa
${ALLOW_ISSUING_OF_CA_CERTS}  ${True}
# Sensitive Service so maybe disallowed
${ALLOW_CMP_EKU_EXTENSION}  ${True}

##### Section 3
#Indicating if the PKIFailInfo must be set correctly.
${FAILINFO_MUST_BE_CORRECT}   ${True}
# For messageTime check.
${MAX_ALLOW_TIME_INTERVAL_RECEIVED}  ${-501}

# DSA is not allowed by RFC9483.
${DSA_KEY}         data/keys/private-key-dsa.pem
${DSA_KEY_PASSWORD}   11111
${DSA_CERT}        data/unittest/dsa_certificate.pem

# Device certificate and key (None means not provided).
${DEVICE_CERT_CHAIN}   data/mock_ca/device_cert_ecdsa_cert_chain.pem
${DEVICE_KEY}  data/keys/private-key-ecdsa.pem
${DEVICE_KEY_PASSWORD}   11111

##### Section 4
# If ALLOW_P10CR is enabled, all generic test cases will be done
# using P10CR because Header checks are body-independent and are only done
# with either CR or P10CR.
${ALLOW_P10CR_MAC_BASED}   ${True}
${ALLOW_CR_MAC_BASED}   ${True}
${ALLOW_IR_MAC_BASED}   ${True}
${ALLOW_KUR_SAME_KEY}    ${False}
${ALLOW_IR_SAME_KEY}   ${True}
${LARGE_KEY_SIZE}    ${12800}
${ALLOW_CERT_CONF}    ${False}

# Section 4.1.6
${ALLOW_KGA}   ${True}
# Whether to allow Ed25519, Ed448, X25519, X448 KGA Requests.
${ALLOW_KGA_RAW_KEYS}   ${False}

# Section 4.2
${REVOCATION_STRICT_CHECK}    ${False}
# The time to wait, until a certificate is revoked, so that
# the test cases can be run.
${REVOKED_WAIT_TIME}   5s
${UPDATE_WAIT_TIME}   3s
${WAIT_UNTIL_UPDATED_CONFIRMATION_IS_EXPIRED}   15s

# Section 4.3
# Whether a Support message can be used with a pre-shared-Secret.
${ALLOW_MAC_PROTECTED_SUPPORT_MSG}   ${True}
${ALLOW_SUPPORT_MESSAGES}   ${True}
# Can be used to check if the General Message CRL Update Retrieval works with the last CRL.
${CRL_FILEPATH}    data/mock_ca/current_crl.pem
${CRL_CERT_IDP}  data/unittest/dsa_certificate.pem


${OLD_ROOT_CERT}   ${None}
${CERT_PROFILE}    base

# Sets the allowed time interval between request and response to 300 seconds.
${ALLOWED_TIME_INTERVAL}   ${300}

# Certificate revocation checks.
${ALLOW_CRL_CHECK}   ${False}
${REVOKE_CERT_ON_ERROR}  ${False}
${REVOKE_CERT_ON_LATE_CONFIRMATION}  ${False}

# Device certificate and key (None means not provided).
${DEVICE_CERT}   ${None}
${DEVICE_KEY}  ${None}

# Section 5.2 and 5.3
# Other trusted PKI and Key (None means not provided, so test are skipped).
${OTHER_TRUSTED_PKI_KEY}    ./data/keys/private-key-ecdsa.pem
${OTHER_TRUSTED_PKI_CERT}    ./data/trusted_ras/ra_cms_cert_ecdsa.pem
# Whether to allow unprotected inner messages, inside a nested PKIMessage.
${ALLOW_UNPROTECTED_INNER_MESSAGE}    True
# The directory containing the certificates to build the trusted RA certificate chain.
${RA_CERT_CHAIN_DIR}    ./data/unittest
# saves the entire certificate chain of the RA.
${RA_CERT_CHAIN_PATH}   ${None}

# A certificate used to verify, if it is supported
# that another trusted PKI Management Entity can revoke a certificate.
${RR_CERT_FOR_TRUSTED}   ${None}

# Relevant for CRR requests.
${TRUSTED_CA_CERT}      ./data/trusted_ras/ra_cms_cert_ecdsa.pem
${TRUSTED_CA_KEY}       ./data/keys/private-key-ecdsa.pem
${TRUSTED_CA_KEY_PASSWORD}   11111
${TRUSTED_CA_DIR}            data/unittest

#### Issuing

# Allowed freshness for the BinaryTime in seconds.
# Used to indicate the maximum time difference between the BinaryTime and the current time.
${ALLOWED_FRESHNESS}   500

# Hybrid Variables
${DEFAULT_TRAD_ALG}    rsa
${DEFAULT_PQ_SIG_ALG}   ml-dsa-44

# Hybrid Endpoints

${INIT_SUFFIX}   issuing
${PQ_ISSUING_SUFFIX}   issuing
${PQ_STATEFUL_ISSUING_SUFFIX}   issuing
${URI_RELATED_CERT}   http://127.0.0.1:${PORT}/cert
${NEG_URI_RELATED_CERT}   http://127.0.0.1:${PORT}/cert_neg
${ISSUING_SUFFIX}   issuing
${COMPOSITE_URL_PREFIX}   issuing
${CATALYST_ISSUING}  catalyst-issuing
${CATALYST_SIGNATURE}   catalyst-sig
${SUN_HYBRID_SUFFIX}   sun-hybrid
${CHAMELEON_SUFFIX}   chameleon
${RELATED_CERT_SUFFIX}   related-cert
${MULTI_AUTH_SUFFIX}   multi-auth
${CERT_DISCOVERY_SUFFIX}   cert-discovery

# CMP and LwCMP certificates and keys
${UPDATED_CERT}    ${None}
${UPDATED_KEY}     ${None}
${DSA_KEY}         ${None}
${DSA_CERT}        ${None}


# Hybrid Certificates and Keys
${ISSUED_KEY}   ${None}
${ISSUED_CERT}   ${None}
${COMPOSITE_KEM_KEY}   ${None}
${COMPOSITE_KEM_CERT}   ${None}
${REVOKED_COMP_KEM_KEY}   ${None}
${REVOKED_COMP_KEM_CERT}   ${None}
${COMPOSITE_KEY}   ${None}
${COMPOSITE_CERT}   ${None}
${REVOKED_COMP_KEY}   ${None}
${REVOKED_COMP_CERT}   ${None}
${UPDATED_COMP_KEY}   ${None}
${UPDATED_COMP_CERT}   ${None}
${CHAM_KEY1}   ${None}
${CHAM_KEY2}   ${None}
${CHAMELEON_CERT}   ${None}
${RELATED_CERT}   ${None}
${RELATED_KEY}   ${None}
${RELATED_CERT_SEC}   ${None}
${RELATED_KEY_SEC}   ${None}

