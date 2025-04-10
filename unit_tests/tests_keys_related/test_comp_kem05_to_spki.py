# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules.rfc5480 import RSAPublicKey

from pq_logic.hybrid_structures import CompositeKEMPublicKey
from resources.keyutils import generate_key


class TestCompositeKEMToSPKI(unittest.TestCase):

    def test_to_spki_rsa(self):
        """
        GIVEN a CompositeKEM key with an RSA traditional key.
        WHEN converting the key to a SubjectPublicKeyInfo structure.
        THEN the structure should be valid.
        """
        composite_kem = generate_key("composite-kem-05",
                                          pq_name="ml-kem-768",
                                          trad_name="rsa")

        der_data = composite_kem.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )

        obj, rest = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(rest, b"")

        keys = obj["subjectPublicKey"].asOctets()

        seq_of, rest = decoder.decode(keys, CompositeKEMPublicKey())
        self.assertEqual(rest, b"")

        obj, rest = decoder.decode(seq_of[1].asOctets(), asn1Spec=RSAPublicKey())
        self.assertEqual(rest, b"")


    def test_to_spki_x25519(self):
        """
        GIVEN a CompositeKEM key with an X25519 traditional key.
        WHEN converting the key to a SubjectPublicKeyInfo structure.
        THEN the structure should be valid.
        """
        composite_kem = generate_key("composite-kem-05", pq_name="ml-kem-768",
                                     trad_name="x25519")
        der_data = composite_kem.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )

        obj, rest = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(rest, b"")

        keys = obj["subjectPublicKey"].asOctets()

        seq_of, rest = decoder.decode(keys, CompositeKEMPublicKey())
        self.assertEqual(rest, b"")

        x25519_key = X25519PublicKey.from_public_bytes(seq_of[1].asOctets())
        self.assertEqual(x25519_key.public_bytes_raw(), composite_kem.public_key().trad_key.encode())
