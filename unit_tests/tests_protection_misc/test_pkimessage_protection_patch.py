# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_csr
from resources.certutils import parse_certificate
from resources.cmputils import build_p10cr_from_csr
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file


class TestPKIMessagePatchCertificate(unittest.TestCase):


    def test_patch_with_cert(self):
        """
        GIVEN a PKIMessage
        WHEN the PKIMessage is protected,
        THEN the PKIMessage is protected.
        """
        rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        csr = build_csr(
            signing_key=rsa_key,
        )
        p10cr = build_p10cr_from_csr(
            csr=csr,
            exclude_fields="senderKID,sender",
        )
        _ = protect_pkimessage(
            p10cr,
            private_key=rsa_key,
            protection="signature",
            cert=cert
        )




