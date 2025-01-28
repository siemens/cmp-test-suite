# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Allows issuing certificates with hybrid keys/and mechanisms.

##############################################################################

Warning:
-------
This does not official ideas how to issue certificates with hybrid keys,
like Catalyst. Some are just Ideas how someone could use the newly developed
mechanisms to issue a certificate.
##############################################################################

"""

from typing import Optional, Sequence, Tuple, Union

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc9480
from resources.ca_ra_utils import (
    build_cp_from_p10cr,
    build_ip_cmp_message,
    get_cert_req_msg_from_pkimessage,
    get_correct_ca_body_name,
    get_public_key_from_cert_req_msg,
    prepare_cert_response,
    prepare_encr_cert_for_request,
    verify_sig_pop_for_pki_request,
)
from resources.certbuildutils import (
    build_cert_from_cert_template,
    build_cert_from_csr,
    prepare_cert_template,
    prepare_sig_alg_id,
    prepare_tbs_certificate_from_template,
    sign_cert,
)
from resources.certextractutils import extract_extension_from_csr, get_extension
from resources.cmputils import (
    patch_pkimessage_header_with_other_message,
    prepare_popo,
    prepare_popo_challenge_for_non_signing_key,
)
from resources.convertutils import copy_asn1_certificate
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyCombination, UnknownOID
from resources.keyutils import generate_key, generate_key_based_on_alg_id
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, PQ_SIG_PRE_HASH_OID_2_NAME, id_ce_altSignatureAlgorithm, \
    id_ce_altSignatureValue
from resources.protectionutils import protect_pkimessage
from resources.typingutils import PrivateKey, TradSigPrivKey
from resources.utils import manipulate_composite_sig, manipulate_first_byte
from robot.api.deco import keyword, not_keyword
from unit_tests.prepare_ca_response import build_ca_pki_message

from pq_logic.hybrid_sig.catalyst_logic import (
    load_catalyst_public_key,
    prepare_alt_sig_alg_id_extn,
    prepare_alt_signature_value_extn,
    prepare_subject_alt_public_key_info_extn,
    sign_cert_catalyst,
)
from pq_logic.hybrid_structures import AltSignatureValueExt
from pq_logic.hybrid_sig.chameleon_logic import \
    build_chameleon_cert_from_paired_csr
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import sun_cert_template_to_cert, sun_csr_to_cert
from pq_logic.keys.abstract_composite import AbstractCompositeSigPrivateKey, AbstractCompositeSigPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey, PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey, HybridKEMPublicKey
from pq_logic.pq_compute_utils import sign_data_with_alg_id, verify_csr_signature, verify_signature_with_alg_id
from pq_logic.trad_typing import ECDHPrivateKey, CA_RESPONSE, CA_CERT_RESPONSE, CA_CERT_RESPONSES


def build_chameleon_from_p10cr(
        request: rfc9480.PKIMessage,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
        **kwargs,
) -> Tuple[rfc9480.PKIMessage, rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Build a Chameleon certificate from a `p10cr` request.


    Arguments:
    ----------
        - `request`: The PKIMessage request.
        - `ca_cert`: The CA certificate matching the CA key.
        - `ca_key`: The CA key to sign the certificate with.
        - `cmp_protection_cert`: The CMP protection certificate. Defaults to `None`.
        (to ensure that the certificate is at the second position)
        - `kwargs`: Additional keyword arguments.

    Returns:
    -------
        - The PKIMessage with the certificate response.
        - The issued paired certificate.
        - The delta certificate.

    Raises:
    -------
        - ValueError: If the request type is not `p10cr`.
        - ValueError: If the key type is invalid.
        - BadAsn1Data: If the ASN.1 data is invalid.
        - BadPOP: If the POP is invalid.

    """
    cert, delta_cert = build_chameleon_cert_from_paired_csr(
        csr=request["body"]["p10cr"],
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    pki_message, cert = build_cp_from_p10cr(cert=cert, request=request, **kwargs)
    if cmp_protection_cert is None:
        pki_message["extraCerts"].append(cmp_protection_cert)

    pki_message["extraCerts"].append(delta_cert)
    return pki_message, cert, delta_cert
