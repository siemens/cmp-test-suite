import json

from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pyasn1.codec.der import encoder
from resources import utils
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key
from resources.envdatautils import prepare_issuer_and_serial_number, prepare_kem_recip_info
from resources.keyutils import generate_key
from unit_tests.utils_for_test import private_key_to_pkcs8

key = generate_key("ml-kem-768")

ir = build_ir_from_key(key)

with open("./ir_ml_kem_768.der", "wb") as f:
    f.write(encoder.encode(ir))
f.close()


def write_kem_recip_info_example() -> None:
    """Generate the KEM Recipient Info example file."""
    ca_cert = parse_certificate(utils.load_and_decode_pem_file("data/unittest/pq_cert_ml_kem_768.pem"))

    d = b"A" * 32
    z = b"B" * 32
    cek = b"C" * 32

    ca_key = MLKEMPrivateKey.key_gen(name="ml-kem-768", d=d, z=z)

    public_key_recip = generate_key("rsa")

    issuer_and_ser = prepare_issuer_and_serial_number(issuer="CN=Null-DN",
                                                      serial_number=0)
    kem_recip_info = prepare_kem_recip_info(
        server_cert=ca_cert,
        public_key_recip=public_key_recip,
        cek=cek,
        issuer_and_ser=issuer_and_ser,
        hybrid_key_recip=None,
    )

    data_map = {
        "kem_recip_info": encoder.encode(kem_recip_info).hex(),
    }
    data_map["ml-kem-768"] = {}
    data_map["ml-kem-768"]["d"] = d.hex()
    data_map["ml-kem-768"]["z"] = z.hex()
    data_map["cek"] = cek.hex()
    data_map["ca_cert"] = encoder.encode(ca_cert).hex()
    data_map["private_key_pkcs8"] = private_key_to_pkcs8(key).hex()
    data_map["private_key_raw_bytes"] = ca_key.private_bytes_raw().hex()

    with open("./kem_recip_info_example.json", "w") as f:
        json.dump(data_map, f, indent=4)
    f.close()


write_kem_recip_info_example()







