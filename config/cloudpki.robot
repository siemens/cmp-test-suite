# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation     An example resource file with configuration options that are meant for use on your local development
...               system. Use this file as a template when adapting the tests to a specific environment.


*** Variables ***
# the dev-environment always runs the latest version
# qa - the stable version
${CA_CMP_URL}    https://broker.sdo-qa.siemens.cloud/.well-known/cmp
${CA_BASE_URL}   https://broker.sdo-qa.siemens.cloud/.well-known/cmp

# The initial issued certificate and key for running the tests.
${ISSUED_KEY}    ${None}
${ISSUED_CERT}   ${None}
# The initial issued certificate and key for running the tests setup.
${INIT_SUFFIX}   ${None}
${INITIAL_KEY_PATH}    ${None}
${INITIAL_CERT_PATH}   ${None}
${INITIAL_KEY_PASSWORD}   ${None}


${PRESHARED_SECRET}    SiemensIT
${SENDER}              CN=CloudCA-Integration-Test-User
${RECIPIENT}           CN=CloudPKI-Integration-Test
${DEFAULT_X509NAME}    CN=CloudCA-Integration-Test-User

##### About Issuing:

# Implicit confirmation allowed.
${ALLOW_IMPLICIT_CONFIRM}  ${True}

# then send always the ${DEFAULT_X509NAME} inside the `CertTemplate` and csr
${ALLOW_ONLY_ONE_SENDER}   ${True}
# for test cases are only the same keys can be used to save resources.
# TODO implement have a list maybe called burned_keys and send each time a new one.
${ALLOW_IR_SAME_KEY}       ${True}
# Could be used to always load the same PKIMessage structure and patch it during testing.
# TODO implement a one dataclass for the PKIMessage to always patch the same message if allowed,
# to have some lax test settings and save as much resources as possible.
${IRELEVANT_messageTime}    ${FALSE}
# Currently does not support strict validation on it.
# MUST be used but if not a strict setting could be ignored.
${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}   ${False}

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
${STRICT}   ${False}
# Test the LWCMP version.
${LWCMP}   ${True}


# IF legacy systems are used, it might be allowed to use,
# to use NULL instead of absent AlgorithmIdentifier `parameters`
${ALLOW_NULL_INSTEAD_OF_ABSENT}   ${False}

# Needs to be the same for cloudpki, so that the server does allow the request.
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
${CA_RSA_ENCR_CERT}    ${None}
${CA_X25519_CERT}   ${None}
${CA_X448_CERT}     ${None}
${CA_ECC_CERT}      ${None}
${CA_HYBRID_KEM_CERT}   ${None}
${CA_KEM_CERT}     ${None}

##### About CertTemplate
${ALLOWED_ALGORITHM}   ed25519,rsa,ecc,ed448,x25519,x448,dsa
${ALLOW_ISSUING_OF_CA_CERTS}  ${True}
# Sensitive Service so maybe disallowed
${ALLOW_CMP_EKU_EXTENSION}  ${True}

##### Section 3
#Indicating if the PKIFailInfo must be set correctly.
${FAILINFO_MUST_BE_CORRECT}=    True
# For messageTime check.
${MAX_ALLOW_TIME_INTERVAL_RECEIVED}  ${-500}

# DSA is not allowed by RFC9483.
${DSA_KEY}         ${None}
${DSA_KEY_PASSWORD}   ${None}
${DSA_CERT}        ${None}

# Device certificate and key (None means not provided).
${DEVICE_CERT_CHAIN}   ${None}
${DEVICE_KEY}  ${None}
${DEVICE_KEY_PASSWORD}   ${None}

##### Section 4
# If ALLOW_P10CR is enabled, all generic test cases will be done
# using P10CR because Header checks are body-independent and are only done
# with either CR or P10CR.
${ALLOW_P10CR_MAC_BASED}   ${True}
${ALLOW_CR_MAC_BASED}   ${False}
${ALLOW_IR_MAC_BASED}   ${False}
${ALLOW_KUR_SAME_KEY}    ${False}
${ALLOW_IR_SAME_KEY}   ${True}
${LARGE_KEY_SIZE}    ${False}
${ALLOW_CERT_CONF}    ${False}

# Section 4.1.6
${ALLOW_KGA}   ${True}
# Whether to allow Ed25519, Ed448, X25519, X448 KGA Requests.
${ALLOW_KGA_RAW_KEYS}   ${False}

# Section 4.2
${REVOCATION_STRICT_CHECK}    ${False}
# The time to wait, until a certificate is revoked, so that
# the test cases can be run.
${REVOKED_WAIT_TIME}   10
${UPDATE_WAIT_TIME}   3


# Section 4.3
# Whether a Support message can be used with a pre-shared-Secret.
${ALLOW_MAC_PROTECTED_SUPPORT_MSG}   ${False}
${ALLOW_SUPPORT_MESSAGES}   ${True}
# Can be used to check if the General Message CRL Update Retrieval works with the last CRL.
${CRL_FILEPATH}    ${None}
${CRL_CERT_IDP}  ${False}

${OLD_ROOT_CERT}   ${None}
${CERT_PROFILE}    ${None}

# Sets the allowed time interval between request and response to 300 seconds.
${ALLOWED_TIME_INTERVAL}   ${300}

# Certificate revocation checks.
${ALLOW_CRL_CHECK}   ${False}
${REVOKE_CERT_ON_ERROR}  ${False}
${REVOKE_CERT_ON_LATE_CONFIRMATION}  ${False}

# Certificates and Keys to set.
${INITIAL_KEY_PATH}    ${None}
${INITIAL_CERT_PATH}   ${None}
${INITIAL_KEY_PASSWORD}   11111

# Device certificate and key (None means not provided).
${DEVICE_CERT}   ${None}
${DEVICE_KEY}  ${None}

# Section 5.2 and 5.3
# Other trusted PKI and Key (None means not provided, so test are skipped).
${OTHER_TRUSTED_PKI_KEY}    ${None}
${OTHER_TRUSTED_PKI_CERT}    ${None}

# A certificate used to verify, if it is supported
# that another trusted PKI Management Entity can revoke a certificate.
${RR_CERT_FOR_TRUSTED}   ${None}

# Relevant for CRR requests.
${TRUSTED_CA_CERT}      ${None}
${TRUSTED_CA_KEY}       ${None}
${TRUSTED_CA_KEY_PASSWORD}   ${None}
${TRUSTED_CA_DIR}            ${None}

# Hybrid Endpoints

${PQ_ISSUING_SUFFIX}    ${None}
${URI_RELATED_CERT}   ${None}
${NEG_URI_RELATED_CERT}   ${None}
${ISSUING_SUFFIX}    ${None}
${COMPOSITE_URL_PREFIX}    ${None}
${CATALYST_SIGNATURE}    ${None}
${SUN_HYBRID_SUFFIX}    ${None}
${CHAMELEON_SUFFIX}    ${None}
${RELATED_CERT_SUFFIX}    ${None}
${MULTI_AUTH_SUFFIX}    ${None}
${CERT_DISCOVERY_SUFFIX}    ${None}

