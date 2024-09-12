import unittest

from resources import cryptoutils


class TestCryptoUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # used for testing PBMAC1
        cls.predefined_salt = b'1234567890abcdef'

    def test_compute_pbmac1(self):
        mac = cryptoutils.compute_pbmac1(b'hello', b'key', hash_alg='sha512', salt=self.predefined_salt)
        self.assertEqual(mac, b'\xc3\xe7\xe5S\xa9<mq(j\xda\x95\x11\x86\xf9\xae$l\x14\x84L\x89\xef\x10\xd21vZa\x1c\xf2\x04A\x9d\x940\x0e\x8f&\xd2\x1fDj=\xaf\xb8B\xc8\x99\xdc\xe2\x8cu\xef;9\xa4\xc2s\xcf\x1d\xcaR\xdc')


    def test_compute_password_based_mac(self):
        mac = cryptoutils.compute_password_based_mac(b'hello', b'key', iterations=5, salt=self.predefined_salt, hash_alg='sha256')
        self.assertEqual(mac, b'\xa8$\xe6\x00\x19\xa1\xd2\x1eX\x0f\xb3`\xe9vp\xa6\xbd\'"B\x9a\xfe\xaf\xa7I\x00d\xe3\xb1\x91\n\xf3')

if __name__ == '__main__':
    unittest.main()
