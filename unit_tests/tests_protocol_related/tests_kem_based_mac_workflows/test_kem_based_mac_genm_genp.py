import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.certutils import parse_certificate
from resources.general_msg_utils import build_general_message, validate_genp_kem_ct_info, \
    build_genp_kem_ct_info_from_genm
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import prepare_kem_ciphertextinfo
from resources.utils import load_and_decode_pem_file


class TestKEMBasedMacGenmGenp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.common_name = "CN=Hans the Tester"
        cls.xwing = load_private_key_from_file("data/keys/private-key-xwing.pem")
        cls.xwing_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing.pem"))

    def test_build_general_message_for_kembasedmac(self):
        """
        GIVEN a KEM key,
        WHEN building a general message,
        THEN the message is correctly built.
        """
        info_val = prepare_kem_ciphertextinfo(
            key=self.xwing,
        )
        genm = build_general_message(
            add_messages=None,
            info_values=info_val,
        )
        self.assertEqual(len(genm["body"]["genm"]), 1)
        der_data = encoder.encode(genm)
        decoded_genm, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
        self.assertEqual(rest, b"")


    def test_build_genp_from_genm(self):
        """
        GIVEN a general message,
        WHEN building a genp message,
        THEN the message is correctly built.
        """
        info_val = prepare_kem_ciphertextinfo(
            key=self.xwing,
        )
        genm = build_general_message(
            add_messages=None,
            info_values=info_val,
        )
        genm["extraCerts"].append(self.xwing_cert)

        der_data = encoder.encode(genm)
        decoded_genm, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())

        ss, genp = build_genp_kem_ct_info_from_genm(
            genm=decoded_genm,
        )
        self.assertEqual(len(genp["body"]["genp"]), 1)
        der_data = encoder.encode(genp)
        decoded_genp, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
        self.assertEqual(rest, b"")


    def test_message_exchange(self):
        """
        GIVEN a complete message exchange,
        WHEN all necessary messages are built,
        THEN the genp message is correctly built
        and the shared secret is correctly decapsulated.
        """
        info_val = prepare_kem_ciphertextinfo(
            key=self.xwing,
        )
        genm = build_general_message(
            add_messages=None,
            info_values=info_val,
        )
        genm["extraCerts"].append(self.xwing_cert)
        der_data = encoder.encode(genm)
        decoded_genm, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())

        ss, genp = build_genp_kem_ct_info_from_genm(
            genm=decoded_genm,
        )
        ss_out = validate_genp_kem_ct_info(
            genp=genp,
            client_private_key=self.xwing,
        )
        self.assertEqual(ss, ss_out)
