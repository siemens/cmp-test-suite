# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
import unittest.mock as mock
from io import StringIO

from resources import asn1dump
from resources.cmputils import parse_pkimessage
from resources.utils import load_and_decode_pem_file


class TestASN1Dump(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = load_and_decode_pem_file("data/cmp-sample-reject.pem")
        cls.asn1_object = parse_pkimessage(raw)

    def test_dump_asn1_schema(self):
        """Load a pyasn1 object, dump its schema and ensure no exceptions occurred."""
        # The dumper prints directly to stdout, so we suppress that here to keep
        # the output of unittest clean.
        with mock.patch('sys.stdout', new=StringIO()):
            asn1dump.dump_asn1_schema(self.asn1_object)


if __name__ == "__main__":
    unittest.main()
