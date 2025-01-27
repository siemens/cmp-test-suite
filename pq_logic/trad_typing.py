# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Includes typing for traditional cryptography keys, to not access `typingutils`."""

from typing import Union, Tuple, List

from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
from pyasn1_alt_modules import rfc9480

ECDHPrivateKey = Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]
ECDHPublicKey = Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]
CA_RESPONSE = Tuple[rfc9480.PKIMessage, List[rfc9480.CMPCertificate]]
CA_CERT_RESPONSE = Tuple[rfc9480.CertResponse, rfc9480.CMPCertificate]
CA_CERT_RESPONSES = Tuple[List[rfc9480.CertResponse], List[rfc9480.CMPCertificate]]
