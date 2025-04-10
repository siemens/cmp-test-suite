# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Includes typing for traditional cryptography keys, to not access `typingutils`."""

from typing import List, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import CertResponseTMP, PKIMessageTMP

ECDHPrivateKey = Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]
ECDHPublicKey = Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]
CA_RESPONSE = Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]
CA_CERT_RESPONSE = Tuple[CertResponseTMP, rfc9480.CMPCertificate]
CA_CERT_RESPONSES = Tuple[List[CertResponseTMP], List[rfc9480.CMPCertificate]]
