# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import logging
import unittest
from cryptography import x509
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5652, rfc5083, rfc9629, rfc5958

from pq_logic.keys.kem_keys import MLKEMPrivateKey
from resources.ca_kga_logic import process_kem_recip_info
from resources.cryptoutils import decrypt_data_with_alg_id
from resources.utils import decode_pem_string


def _parse_kem_recipient_info(recip_info: rfc5652.RecipientInfo) -> rfc9629.KEMRecipientInfo:
    """Parse KEMRecipientInfo from OtherRecipientInfo."""
    ori = recip_info['ori']
    if ori['oriType'] != rfc9629.id_ori_kem:
        raise ValueError(f"Unsupported OtherRecipientInfo type: {ori['oriType']}")

    ori_value = ori['oriValue']
    kem_info, _ = decoder.decode(ori_value.asOctets(), asn1Spec=rfc9629.KEMRecipientInfo())
    return kem_info

def _parse_auth_env_data(data: bytes) -> rfc5083.AuthEnvelopedData:
    """Parse AuthEnvelopedData from raw bytes."""
    content_info, _ = decoder.decode(data, asn1Spec=rfc5652.ContentInfo())
    oid = content_info['contentType']

    if str(oid) != '1.2.840.113549.1.9.16.1.23':
        raise ValueError(f"Not a CMS AuthEnvelopedData object. Got: {oid}")

    return decoder.decode(content_info["content"], asn1Spec=rfc5083.AuthEnvelopedData())[0]

def _process_auth_env_data(auth_env: rfc5083.AuthEnvelopedData):
    """Process AuthEnvelopedData by extracting the necessary data."""

    recipient_infos = auth_env["recipientInfos"]
    kem_info = _parse_kem_recipient_info(recipient_infos[0])
    enc_content = auth_env["authEncryptedContentInfo"]

    auth_attrs = None if not auth_env["authAttrs"].isValue else encoder.encode(auth_env["authAttrs"])
    mac = None if not auth_env["mac"].isValue else auth_env["mac"].asOctets()

    return kem_info, enc_content, auth_attrs, mac

def _decrypt_auth_enveloped(data: bytes, recip_priv_key: MLKEMPrivateKey) -> bytes:
    """Decrypt AuthEnvelopedData using the recipient's private key."""

    auth_env = _parse_auth_env_data(data)

    kem_info, enc_content, auth_attrs, mac = _process_auth_env_data(auth_env)
    cek = process_kem_recip_info(kem_recip_info=kem_info, private_key=recip_priv_key, server_cert=None, for_pop=True)
    logging.info(f"CEK: {cek.hex()}")

    alg_id = enc_content["contentEncryptionAlgorithm"]
    ciphertext = enc_content["encryptedContent"].asOctets()

    return decrypt_data_with_alg_id(alg_id=alg_id,
                                    key=cek,
                                    data=ciphertext,
                                    mac=mac,
                                    auth_attrs=auth_attrs,
                                    # is not set correctly inside the RFC.
                                    allow_bad_gcm_size=True,
                                    )

env_data = b"""\
-----BEGIN CMS-----
MIID8gYLKoZIhvcNAQkQARegggPhMIID3QIBADGCA4ikggOEBgsqhkiG9w0BCRAN
AzCCA3MCAQCAFFmXiMN67UAO5AXRsqM2arF9gkpRMAsGCWCGSAFlAwQEAQSCAwDz
6kG2NhIUhlAHMA3HCeC8G9o0Ey8HMa//d2N7a7e92ba+Xrwfp9NKfiwH3r26CvqG
Aj5LgU/hbzNkFGw1AfgXDQTcpHEjfPB2R/x6OxiuV6KPxOjqHbjDvyRoclHHrGfG
i4uBkgPSAXrBlzXop9n7F4sxae2grAJIWX8sl/Vs6BRcKmuAIXbriZTQnEoojgyr
ncDz3owBMBdLvA7STNEJ9vt3WaGV07/3qjSCHsxynDwWpiHYwf3Q++/VlZNrPnzZ
B/ulQtAWweHxgTpvX0k8WnCKSl9S5qGIMK2Tc4KBMSqb02pkSMDV/YEKCwPyFgIO
hEleCys+umJmUAbGm0cmH0Kev0sHAnYvg02uebvK2xFW6uboTy0Txj8okoy5sP6h
mRekF6qgrEEa3/CjkSAxW9iv986h64UUU0cWZeEaEl0eYR6LOf3e16ZPSYDC8Xo7
VjAZvYuf8QuLlqDCw73Rp+PT+fkFqfY4dxGXwZYMU/UOuQqi2IsT86W8gmsQPhEv
7EvSScX8TJSDsrQOVrGoHc5OymRmuepkn17ORYyrR8iKEDVJEDCGesJbgcCoi2VT
LFdDYOzMn1T6gSsmyg3KGWLqdn8csG/mPjKblyBmlYbM8KT4ICqQx1nBngGUfMIV
+v4wY9s0vcLSTBI5QCbgPRrIzz0B97sZdcp29uXA4Qlz2riuRpn38up1G90BGxvo
lukVQ8djNhhGgC60UJwA3bRn+O2xo/cSBkMSLJIIqA5QSY+zcPu90MqvN1JFkbO6
YJQbtuFvQ9hAmHJNrWRaXRGLJuH8gxUhG2bhOn5jjtgmVdKHx8gFDxHs13IQMHAU
//u5JHvJOnC8HLWPIbMTXa0giC7H22Gf7GMdYVG0pNr37wEJkfd7D4OKM5S0fXH3
4moC701Bgypt0D+inpqd+Vdyzylg5KkkoLcQqiE1tAPYc2FCSJNhZe/xA4/WOkoO
HS6/FvFcNaIxkwmNDl9BM4J+Zv4zxqcrqjSUuRM9r/IepBU22+EltUGXug15v+Mw
DQYLKoZIhvcNAQkQAxwCASAwCwYJYIZIAWUDBAEtBCgSWjJGbANW6249qJezunw8
TekPnqeXQxQsCApolNdBREvHJzVFD8fxMDoGCSqGSIb3DQEHATAeBglghkgBZQME
AS4wEQQM09P1v4RTaKUfxd6/AgEQgA0W/2sAf/+wpWYbxab8BBAcFxeZJbrC7Ifl
jQHB7vah
-----END CMS-----
"""



bob_private_key_pem = """-----BEGIN PRIVATE KEY-----
MFICAQAwCwYJYIZIAWUDBAQBBEAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
HB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/
-----END PRIVATE KEY-----"""

def _load_private_key() -> MLKEMPrivateKey:
    """Load Bob's ML-KEM-512 private key from the PEM string."""
    data_private = decode_pem_string(bob_private_key_pem)
    obj, _ = decoder.decode(data_private, asn1Spec=rfc5958.OneAsymmetricKey())
    data_private = obj["privateKey"].asOctets()
    loaded_key = MLKEMPrivateKey.from_private_bytes(name="ml-kem-512", data=data_private)
    return loaded_key

class TestAuthEnvData(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # based on: https://www.ietf.org/archive/id/draft-ietf-lamps-cms-kyber-08.html Appendix C.
        cls.bob_private_key = _load_private_key()
        bob_public_key_ski = "599788c37aed400ee405d1b2a3366ab17d824a51"
        pub_key_ski = x509.SubjectKeyIdentifier.from_public_key(
            cls.bob_private_key.public_key()).digest.hex().lower() # type: ignore

        if bob_public_key_ski != pub_key_ski:
            raise ValueError("Failed to load Bob's private key")

        cls.der_env_data = decode_pem_string(env_data)

    def test_decrypt_auth_enveloped(self):
        """
        GIVEN a CMS AuthEnvelopedData structure.
        WHEN the AuthEnvelopedData is decrypted.
        THEN the plaintext should be "Hello, world!".
        """
        plaintext = _decrypt_auth_enveloped(self.der_env_data, self.bob_private_key)
        self.assertEqual(plaintext, b"Hello, world!")

