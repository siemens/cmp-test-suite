# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import tag
from pyasn1_alt_modules import rfc5652

from resources.envdatautils import build_env_data_for_exchange, prepare_issuer_and_serial_number
from resources.extra_issuing_logic import validate_rid_for_encrypted_rand
from resources.keyutils import generate_key, load_private_key_from_file


class TestValidateRidEncryptedRandom(unittest.TestCase):

    def test_validate_encrypted_random_kari(self):
        """
        GIVEN a valid issuer and serial number for a KARI RecipientInfo.
        WHEN the encrypted random is validated.
        THEN the issuer and serial number are successfully validated.
        """
        ec_key = generate_key("ec")

        issuer_and_ser = prepare_issuer_and_serial_number(
            issuer="Null-DN",
            serial_number=0,
        )

        env_data = build_env_data_for_exchange(
            public_key_recip=ec_key.public_key(),
            data=b"encrypted_random",
            issuer_and_ser=issuer_and_ser,
            private_key=ec_key,
        )
        validate_rid_for_encrypted_rand(
            env_data=env_data,
            cert_req_id=0,
        )

    def test_validate_kem_recip_info(self):
        """
        GIVEN a valid issuer and serial number for a KEM RecipientInfo.
        WHEN the encrypted random is validated.
        THEN the issuer and serial number are successfully validated.
        """
        kem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem")

        issuer_and_ser = prepare_issuer_and_serial_number(
            issuer="Null-DN",
            serial_number=0,
        )

        env_data = build_env_data_for_exchange(
            public_key_recip=kem_key.public_key(),
            data=b"encrypted_random",
            issuer_and_ser=issuer_and_ser,
        )

        target = rfc5652.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                                     tag.tagFormatSimple,
                                                                     0))

        der_data = encoder.encode(env_data)
        target, _ = decoder.decode(der_data, asn1Spec=target)


        validate_rid_for_encrypted_rand(
            env_data=target,
            cert_req_id=0,
        )

    def test_validate_encrypted_random_katr(self):
        """
        GIVEN a valid issuer and serial number for a KARI RecipientInfo.
        WHEN the encrypted random is validated.
        THEN the issuer and serial number are successfully validated.
        """
        rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

        issuer_and_ser = prepare_issuer_and_serial_number(
            issuer="Null-DN",
            serial_number=0,
        )
        env_data = build_env_data_for_exchange(
            public_key_recip=rsa_key.public_key(),
            data=b"encrypted_random",
            issuer_and_ser=issuer_and_ser,
        )
        validate_rid_for_encrypted_rand(
            env_data=env_data,
            cert_req_id=0,
        )


    def test_validate_encrypted_random_kari_invalid(self):
        """
        GIVEN an invalid issuer and serial number for a KARI RecipientInfo.
        WHEN the encrypted random is validated.
        THEN an exception should be raised.
        """
        ec_key = generate_key("ec")

        issuer_and_ser = prepare_issuer_and_serial_number(
            issuer="CN=Null-DN",
            serial_number=0,
        )

        env_data = build_env_data_for_exchange(
            public_key_recip=ec_key.public_key(),
            data=b"invalid_encrypted_random",
            issuer_and_ser=issuer_and_ser,
            private_key=ec_key,
        )

        with self.assertRaises(Exception):
            validate_rid_for_encrypted_rand(
                env_data=env_data,
                cert_req_id=-1,
            )



