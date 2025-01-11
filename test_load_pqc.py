import argparse
import glob
import os
import shutil
import zipfile
import subprocess

import cryptography
import pyasn1
from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480


from pq_logic.hybrid_sig.catalyst_logic import verify_catalyst_signature, verify_catalyst_signature_migrated
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPublicKey
from pq_logic.pq_compute_utils import verify_signature
from resources.certutils import parse_certificate
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import get_hash_from_oid
from resources.oidutils import PQ_OID_2_NAME, CMS_COMPOSITE_OID_2_NAME, PQ_KEM_OID_2_NAME
from resources.protectionutils import verify_rsassa_pss_from_alg_id
from resources.utils import load_and_decode_pem_file


def main():
    # Define repository URL and target directory
    repo_url = "https://github.com/IETF-Hackathon/pqc-certificates"
    data_dir = "./data"
    providers_dir = os.path.join(data_dir, "pqc-certificates", "providers")
    pem_files = []

    # Clone the repository using subprocess if not already cloned
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    repo_path = os.path.join(data_dir, "pqc-certificates")
    if not os.path.exists(repo_path):
        print("Cloning repository...")
        subprocess.run(["git", "clone", repo_url, repo_path], check=True)
    else:
        print("Repository already cloned.")

    # Walk through the providers directory
    if os.path.exists(providers_dir):
        for root, dirs, files in os.walk(providers_dir):
            for file in files:
                if file.startswith("artifacts_") and file.endswith(".zip"):
                    zip_path = os.path.join(root, file)
                    print(f"Found zip file: {zip_path}")

                    # Extract the zip file
                    extract_dir = os.path.join(root, "extracted", os.path.splitext(file)[0])
                    os.makedirs(extract_dir, exist_ok=True)

                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)

                    # Find .pem files in the extracted content
                    for subdir, _, extracted_files in os.walk(extract_dir):
                        for extracted_file in extracted_files:
                            if extracted_file.endswith(".der"):
                                pem_path = os.path.join(subdir, extracted_file)
                                pem_files.append(pem_path)



def verify_cert_sig(cert: rfc9480.CMPCertificate, verify_catalyst: bool = False):
    """Verify the signature of a certificate using the appropriate algorithm.

    :param cert: The certificate (`CMPCertificate`) to be verified.
    :raises ValueError: If the algorithm OID in the certificate is unsupported or invalid.
    :raises InvalidSignature: If the signature verification fails.
    """
    alg_id = cert["tbsCertificate"]["signature"]
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    public_key = load_public_key_from_spki(spki)

    if spki["algorithm"]["algorithm"] in PQ_KEM_OID_2_NAME:
        return public_key.name

    signature = cert["signature"].asOctets()
    data = encoder.encode(cert["tbsCertificate"])

    if PQ_KEM_OID_2_NAME.get(alg_id["algorithm"]):
        return PQ_KEM_OID_2_NAME.get(alg_id["algorithm"])

    return verify_signature_with_alg_id(public_key, alg_id, data, signature, verify_catalyst=verify_catalyst)



def verify_signature_with_alg_id(public_key, alg_id: rfc9480.AlgorithmIdentifier,
                                 data: bytes, signature: bytes, verify_catalyst: bool = False):
    """Verify the provided data and signature using the given algorithm identifier.

    Supports traditional-, pq- and composite signature algorithm.

    :param public_key: The public key object used to verify the signature.
    :param alg_id: An `AlgorithmIdentifier` specifying the algorithm and any
                   associated parameters for signature verification.
    :param data: The original message or data whose signature needs verification,
                 as a byte string.
    :param signature: The digital signature to verify, as a byte string.

    :raises ValueError: If the algorithm identifier is unsupported or invalid.
    :raises InvalidSignature: If the signature does not match the provided data
                              under the given algorithm and public key.
    """
    oid = alg_id["algorithm"]

    if verify_catalyst:
        verify_catalyst_signature_migrated(cert)

    elif oid in CMS_COMPOSITE_OID_2_NAME:
        name: str = CMS_COMPOSITE_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = name.startswith("hash-")
        public_key: CompositeSigCMSPublicKey
        public_key.verify(data=data, signature=signature, use_pss=use_pss, pre_hash=pre_hash)
        return public_key.get_name(use_pss=use_pss, pre_hash=pre_hash)

    elif oid in PQ_OID_2_NAME:
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        verify_signature(public_key, signature=signature, data=data, hash_alg=hash_alg)
        return public_key.name
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key).__name__}.")


if __name__ == "__main__":
    pem_files = []

    parser = argparse.ArgumentParser(description="Verify the signatures of the certificates in the pqc-certificates repository.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing files.")
    args = parser.parse_args()

    if args.overwrite:
        print("Overwriting existing files.")
        shutil.rmtree("./data/pqc-certificates")
        main()

    elif not os.path.isdir("./data/pqc-certificates"):
        main()
    else:
       # for file in glob.iglob(f"{dir_path}/**/*.crl", recursive=True):
       for file in glob.iglob("./data/pqc-certificates/providers/**", recursive=True):
           if file.endswith(".der"):
               pem_files.append(file)

       f = open("validation_pem_files.txt", "w", encoding='utf-8')
       f.write(f"Collected {len(pem_files)}.pem files:\n\n")
       for pem in pem_files:
           try:
               data = open(pem, "rb").read()
               cert = parse_certificate(data)
               name = verify_cert_sig(cert, verify_catalyst=True if "catalyst" in pem else False)
               f.write(f"VALID SIGNATURE Key_name: {name}\t{pem}\n")
           except InvalidSignature:
              f.write(f"INVALID SIGNATURE\t{pem}\n")
           except ValueError as e:
               f.write(f"{pem}\t{e}\n")
           except pyasn1.error.PyAsn1Error as e:
                f.write(f"{pem}\tUnable to decode.{e}\n")
           except cryptography.exceptions.UnsupportedAlgorithm as e:
               f.write(f"{pem}\tUnable to decode.{e}\n")


       f.close()
