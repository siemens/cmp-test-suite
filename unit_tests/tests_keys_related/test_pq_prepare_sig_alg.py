import unittest

from pq_logic.keys.sig_keys import SLHDSAPrivateKey
from resources.certbuildutils import prepare_sig_alg_id
from resources.keyutils import generate_key
from resources.oidutils import SLH_DSA_NAME_2_OID, sig_algorithms_oid


class TestPqPrepareSigAlg(unittest.TestCase):

    def test_prepare_slh_dsa_without_prehash(self):
        """
        GIVEN a SLH-DSA key.
        WHEN signature algorithm is prepared without a hash algorithm.
        THEN the OID should be successfully generated.
        """
        key: SLHDSAPrivateKey = generate_key("slh-dsa-shake-256f")
        oid = prepare_sig_alg_id(signing_key=key, hash_alg=None, use_rsa_pss=False)
        id_slh_dsa_shake_256f_with_shake256 = str(sig_algorithms_oid + (31,))
        self.assertEqual(str(oid["algorithm"]), id_slh_dsa_shake_256f_with_shake256)


    def test_prepare_slh_dsa_with_prehash(self):
        """
        GIVEN a SLH-DSA key.
        WHEN signature algorithm is prepared with SHAKE256.
        THEN the OID should be successfully generated.
        """
        key: SLHDSAPrivateKey = generate_key("slh-dsa-shake-256f")
        oid = prepare_sig_alg_id(signing_key=key, hash_alg="shake256", use_rsa_pss=False)
        id_slh_dsa_shake_256f_with_shake256 = str(sig_algorithms_oid + (46,))
        self.assertEqual(str(oid["algorithm"]), id_slh_dsa_shake_256f_with_shake256)


