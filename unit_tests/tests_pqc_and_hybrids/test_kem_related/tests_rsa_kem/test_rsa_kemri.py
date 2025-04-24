# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# codespell: ignore

import base64
import unittest
from typing import Tuple

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5652, rfc9480, rfc9629
from resources.ca_kga_logic import process_kem_recip_info
from resources.keyutils import load_private_key_from_file

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

        fpath = "data/rfc_data/rsa_kem_rfc9696_private_key.pem"
        bob_private_key = load_private_key_from_file(fpath, password=None)

        cek = process_kem_recip_info(
            kem_recip_info=kem_recip_info,
            private_key=bob_private_key,
            server_cert=None,
            for_pop=True,
        )
        self.assertEqual(cek.hex(), "77f2a84640304be7bd42670a84a1258b")
