# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# codespell: ignore
import base64
import unittest
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5652, rfc9480, rfc9629
from resources.ca_kga_logic import process_kem_recip_info
from resources.utils import decode_pem_string

bob_private_key_pem = b"""\
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
"""

cms_data_base64 = """\
MIICXAYJKoZIhvcNAQcDoIICTTCCAkkCAQMxggIEpIICAAYLKoZIhvcNAQkQDQMw
ggHvAgEAgBSe62fJuVp01E0vFjlmgOgBtcuknDAJBgcogYxxAgIEBIIBgMBx/Cc6
+Oe9sVLga/czEDYQdBVKQ6vPPJPBNJnSBlNEPu2e9dPAaF5Kp2poVIFbuXaR/5+N
rBXup9dPRSvzUKZGFj1oKI6XjL96cwie5ScS+aT0ngas57vIWrFNTjNsl8VyiiZU
E4x7JuiDXGsKn77SZJXE6t90Wikzvig/aoixZpX8BmZoc8+202cY7zN2zvwQDDlB
88SUlEB4MlgHpVkYa5XMq/NxTPr3n4O9MFN/3ZrtWkzcvYvQSG+u1z6dSGswh9bI
BlRrbiZxV1yYRh5EH2VUK9ld4m0PU6ZOeEjXMdlgjQU+jTRVRmAthiNv/jcEyYrV
kUTzCJ5ebVJ7VJe6EDx51i6A0CNUELBvcafZvRw4AA+RDWMS6i8go1V1Na0Bswk/
tffuUHCA0Pd9SMnDs3lva33TeGCF+4lRI/BMofHBviLHR6jfrOMjcPsNVweD4n27
fnT8qU7jlnb949ipVT2HgiRzbjfhkdq5U8fiKMB61coxIkIcFN69ByqatjAbBgor
gQUQhkgJLAECMA0GCWCGSAFlAwQCAQUAAgEQMAsGCWCGSAFlAwQBBQQYKHguXT15
SnYWuGP7z8cZt48S3gjPKG4JMDwGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEEgM
yv66vvrO263eyviId4GAEMbKZdt73Xaw834vq2Jktm0=
"""


def load_cms_bytes() -> bytes:
    """Decode the above Base64 string into raw bytes.

    :return: The raw bytes of the CMS EnvelopedData structure.
    """
    return base64.b64decode(cms_data_base64)



def parse_cms_kemri(der_data: bytes) -> Tuple[rfc9629.KEMRecipientInfo, bytes, rfc9480.AlgorithmIdentifier]:
    """Parse a CMS EnvelopedData structure with a KEMRecipientInfo recipient.

    :param der_data: The (DER) data corresponding to the CMS EnvelopedData.
    :return: The parsed KEMRecipientInfo structure, the encrypted content, and the content encryption algorithm.
    """
    content_info, _ = decoder.decode(der_data, asn1Spec=rfc5652.ContentInfo())
    env_data, _ = decoder.decode(content_info["content"], asn1Spec=rfc5652.EnvelopedData())

    enc_content = env_data["encryptedContentInfo"]["encryptedContent"].asOctets()
    cek_alg_id = env_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]
    recip_info = env_data["recipientInfos"][0]["ori"]

    if recip_info["oriType"] != rfc9629.id_ori_kem:
        raise ValueError("RecipientInfo not of type KEM")

    kem_recip_info, _ = decoder.decode(recip_info["oriValue"], asn1Spec=rfc9629.KEMRecipientInfo())

    return kem_recip_info, enc_content, cek_alg_id


class TestRSAKEMRI(unittest.TestCase):
    def test_process_rsa_kemri(self):
        """
        GIVEN a CMS EnvelopedData structure with a KEMRecipientInfo recipient.
        WHEN the KEMRecipientInfo is processed.
        THEN should the correct CEK be returned.
        """
        kem_recip_info, _, _ = parse_cms_kemri(load_cms_bytes())

        der_data = decode_pem_string(bob_private_key_pem)
        bob_private_key = serialization.load_der_private_key(der_data, password=None)

        cek = process_kem_recip_info(
            kem_recip_info=kem_recip_info,
            private_key=bob_private_key,
            server_cert=None,
            for_pop=True,
        )
        self.assertEqual(cek.hex(), "77f2a84640304be7bd42670a84a1258b")
