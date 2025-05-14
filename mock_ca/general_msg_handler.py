# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""General Message Handler for the Mock CA."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1.type.base import Asn1Type
from pyasn1_alt_modules import rfc3565, rfc5280, rfc9480, rfc9481
from pyasn1_alt_modules.rfc9480 import InfoTypeAndValue

from mock_ca.rev_handler import RevocationHandler
from pq_logic.tmp_oids import id_it_KemCiphertextInfo
from resources import cmputils, keyutils
from resources.asn1_structures import (
    AlgorithmIdentifiers,
    CertProfileValueAsn1,
    CRLSourceAsn1,
    CRLStatusAsn1,
    CRLStatusListValueAsn1,
    OIDs,
    PKIMessageTMP,
)
from resources.ca_kga_logic import validate_enveloped_data
from resources.ca_ra_utils import prepare_new_root_ca_certificate, set_ca_header_fields
from resources.cmputils import prepare_pki_message
from resources.compareutils import (
    find_name_inside_general_names,
    find_rel_dis_name_in_name,
)
from resources.convertutils import (
    ensure_is_kem_pub_key,
    ensure_is_sign_key,
    pyasn1_time_obj_to_py_datetime,
)
from resources.exceptions import BadAsn1Data, BadRequest, BadValueBehavior
from resources.general_msg_utils import (
    _prepare_kem_ct_info,
    prepare_supported_language_tags,
    prepare_unsupported_oids_response,
)
from resources.keyutils import load_private_key_from_file
from resources.oidutils import (
    HYBRID_SIG_OID_2_NAME,
    PQ_SIG_OID_2_NAME,
)
from resources.prepare_alg_ids import get_all_supported_ecc_alg_ids, prepare_alg_id
from resources.protectionutils import get_protection_type_from_pkimessage
from resources.typingutils import EnvDataPrivateKey, SignKey
from resources.utils import get_openssl_name_notation
from unit_tests.utils_for_test import compare_pyasn1_objects, try_decode_pyasn1

ABSENT_INFO_TYPES = {
    rfc9480.id_it_caProtEncCert,
    rfc9480.id_it_encKeyPairTypes,
    rfc9480.id_it_signKeyPairTypes,
    rfc9480.id_it_keyPairParamReq,
    rfc9480.id_it_preferredSymmAlg,
    rfc9480.id_it_caCerts,
    rfc9480.id_it_currentCRL,
    rfc9480.id_it_implicitConfirm,
    rfc9480.id_it_certReqTemplate,
    id_it_KemCiphertextInfo,
}


def _try_decode_mock_ca(entry: bytes, expected_type: Asn1Type) -> Any:
    """Try to decode the entry."""
    out, rest = try_decode_pyasn1(entry, expected_type)
    if rest:
        raise BadAsn1Data(type(expected_type).__name__)
    return out  # type: ignore


@dataclass
class GeneralMsgState:
    """State for the general message handler.

    Attributes
    ----------
        - `rev_passphrases`: The revocation passphrases.
        - `shared_secrets`: The transaction ID mapping to the shared secret.

    """

    rev_passphrases: List[bytes] = field(default_factory=list)
    shared_secrets: Dict[bytes, bytes] = field(default_factory=dict)


class GeneralMessageHandler:
    """Handler for general messages."""

    def __init__(
        self,
        root_ca_cert: rfc9480.CMPCertificate,
        root_ca_key: SignKey,
        rev_handler: RevocationHandler,
        enforce_lwcmp: bool = True,
        password: Union[str, bytes] = b"SiemensIT",
        all_relevant_env_certs: Optional[List[rfc9480.CMPCertificate]] = None,
        prot_enc_cert: Optional[rfc9480.CMPCertificate] = None,
        prot_enc_key: Optional[EnvDataPrivateKey] = None,
        ca_cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
        crl_url: str = "http://127.0.0.1/crl",
    ):
        """Initialize the handler.

        :param root_ca_cert: The root CA certificate.
        :param root_ca_key: The root CA private key.
        :param enforce_lwcmp: Whether to enforce the LW-CMP.
        :param password: The password for the revocation passphrase.
        :param rev_handler: The revocation handler.
        :param all_relevant_env_certs: All relevant certificates for the Mock CA,
        to securely exchange sensitive information with the CA.
        (the other certs are added to the `extraCerts` field of the PKIMessage).
        :param prot_enc_cert: The protocol encryption certificate.
        :param prot_enc_key: The protocol encryption key.
        :param ca_cert_chain: The CA certificate chain.
        :param crl_url: The CRL URL. Defaults to "http://127.0.0.1/crl".
        """
        self.sender = "CN=Mock CA"
        self.root_ca_cert = root_ca_cert
        self.root_ca_key = root_ca_key
        self.enforce_lwcmp = enforce_lwcmp
        self.state = GeneralMsgState()
        self.password = password
        self.rev_handler = rev_handler
        self.prot_enc_cert = prot_enc_cert
        self.prot_enc_key = prot_enc_key
        # could be updated to contain all relevant certificates for
        # the Mock CA.
        self.ca_certs = ca_cert_chain or [self.root_ca_cert]
        # For the `id_it_certReqTemplate` info type.
        # So that the user knows that the required RSA key length is 2048 bits.
        self.rsa_req_length = 2048
        self.add_env_data_certs = False
        self.all_rel_env_data_certs = all_relevant_env_certs
        self.crl_url = crl_url
        self.supports_implicit_confirm = True
        self.known_cert_profiles = ["base"]

    def _check_general_message(self, pki_message: PKIMessageTMP) -> None:
        """Check the general message."""
        if self.enforce_lwcmp and len(pki_message["body"]["genm"]) > 1:
            raise BadRequest("The message is not a single general message.")

        if len(pki_message["body"]["genm"]) == 0:
            raise BadRequest("The general message is empty.")

    @staticmethod
    def process_absent_info_type(entry: rfc9480.InfoTypeAndValue) -> None:
        """Process an absent info type."""
        if entry["infoType"] in ABSENT_INFO_TYPES:
            if entry["infoValue"].isValue:
                raise BadValueBehavior(f"For the oid {entry['infoType']} must the `infoValue` be absent.")

    def patch_genp_message_for_extra_certs(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Patch the general message for extra certificates

        So that the signature protection is valid and the extra certificates are added.
        """
        if self.add_env_data_certs:
            if self.all_rel_env_data_certs:
                pki_message["extraCerts"].extend(self.all_rel_env_data_certs)
            else:
                logging.warning("The extra certificates are not set.")

            self.add_env_data_certs = False

        return pki_message

    def prepare_genp_response(
        self,
        pki_message: PKIMessageTMP,
        content: List[rfc9480.InfoTypeAndValue],
        texts: Optional[List[str]] = None,
    ) -> PKIMessageTMP:
        """Prepare a general message response."""
        for_mac = get_protection_type_from_pkimessage(pki_message) == "mac"
        kwargs = set_ca_header_fields(pki_message, {})
        kwargs["sender"] = self.sender
        response = prepare_pki_message(**kwargs, for_mac=for_mac, pki_free_text=texts)
        response["body"]["genp"].extend(content)
        return response

    def process_general_msg(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process a general message."""
        self._check_general_message(pki_message)

        processed = []
        texts = []

        for entry in pki_message["body"]["genm"]:
            self.process_absent_info_type(entry)
            out, text = self._process_general_message_entry(entry, pki_message)
            processed.append(out)
            if text:
                texts.append(text)
        return self.prepare_genp_response(pki_message, processed, texts=texts)

    def _process_general_message_entry(
        self, entry: rfc9480.InfoTypeAndValue, pki_message: PKIMessageTMP
    ) -> Tuple[rfc9480.InfoTypeAndValue, Optional[str]]:
        """Process a general message entry."""
        oid = entry["infoType"]

        if oid == id_it_KemCiphertextInfo:
            return self._process_kem_ciphertext_info(entry=entry, pki_message=pki_message), None

        if oid == rfc9480.id_it_caProtEncCert:
            return self._process_ca_prot_enc_cert(entry)

        if oid == rfc9480.id_it_signKeyPairTypes:
            return self._process_sign_key_pair_types()

        if oid == rfc9480.id_it_encKeyPairTypes:
            return self.process_enc_key_pair_types(entry)

        if oid == rfc9480.id_it_preferredSymmAlg:
            return self.process_preferred_sym_alg(entry)

        if oid == rfc9480.id_it_currentCRL:
            return self.process_current_crl(entry)

        if oid == rfc9480.id_it_unsupportedOIDs:
            # NOT an official solution, but for the help of the user,
            # we'll return all unsupported OIDs.
            return self.process_unsupported_oids(entry)

        if oid == rfc9480.id_it_keyPairParamReq:
            return self._process_key_pair_param_req(entry)

        if oid == rfc9480.id_it_revPassphrase:
            return self.process_rev_passphrase(entry, pki_message)

        if oid == rfc9480.id_it_suppLangTags:
            return self.process_supp_lang_tags(entry=entry)

        if oid == rfc9480.id_it_rootCaKeyUpdate:
            return self._process_root_ca_key_update()

        if oid == rfc9480.id_it_rootCaCert:
            return self._process_root_ca_cert(entry)

        if oid == rfc9480.id_it_certReqTemplate:
            return self._process_cert_req_template()

        if oid == rfc9480.id_it_crlStatusList:
            return self.process_crl_update_retrieval(entry)

        if oid == rfc9480.id_it_caCerts:
            return self._process_ca_certs()

        if oid == rfc9480.id_it_implicitConfirm:
            return self._process_implicit_confirm(entry)

        if oid == rfc9480.id_it_certProfile:
            return self._process_cert_profile(entry), "The certificate profile is not implemented."

        raise NotImplementedError(f"The processing of the info type {entry['infoType']} is not implemented.")

    def _process_cert_profile(self, entry: rfc9480.InfoTypeAndValue) -> rfc9480.InfoTypeAndValue:
        """Process the certificate profile."""
        # GenMsg: {id-it 21}, CertProfileValue
        # Could maybe be used to check if the CertProfile is supported/known?
        cert_profiles = _try_decode_mock_ca(entry["infoValue"].asOctets(), CertProfileValueAsn1())  # type: ignore
        cert_profiles: CertProfileValueAsn1
        if len(cert_profiles) == 0:
            raise BadRequest("The certificate profiles sequence is empty.")

        if len(cert_profiles) != 1:
            raise BadRequest("The certificate profiles sequence length is not 1.")

        entry = cert_profiles[0].prettyPrint()
        if entry not in self.known_cert_profiles:
            raise BadRequest("The certificate profile is not known by the CA.")

        raise BadRequest(
            "The certificate profile is not supposed to be used individually."
            "Please add it inside the `generalInfo` field, with the `CertReqTemplateValue` general message."
        )

    def _process_implicit_confirm(self, entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process the implicit confirm info type."""
        # GenMsg: {id-it 5}, < absent >
        # Could maybe be used to check if the implicitConfirm is allowed?
        if entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the implicit confirm is set.")

        if entry["infoType"] != rfc9480.id_it_implicitConfirm:
            raise BadRequest("The info type for the implicit confirm is not set.")

        _ = _try_decode_mock_ca(entry["infoValue"].asOctets(), rfc9480.ImplicitConfirmValue())

        if not self.supports_implicit_confirm:
            raise BadRequest("The implicit confirm is not supported.")

        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = rfc9480.id_it_implicitConfirm
        info_value["infoValue"] = rfc9480.ImplicitConfirmValue("")
        return info_value, "The implicit confirmation is implemented."

    def _process_root_ca_key_update(self):
        """Process a root CA key update."""
        # GenMsg:    {id-it 18}, RootCaKeyUpdateValue
        raise BadRequest(
            "The root CA key update is used by a client, but "
            "used by the CA to notify the client about the new key and certificate."
        )

    @staticmethod
    def process_unsupported_oids(entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process the unsupported OIDs."""
        #  GenRep: {id-it 7}, SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER

        try_decoded = _try_decode_mock_ca(entry["infoValue"].asOctets(), OIDs())
        try_decoded: OIDs
        return prepare_unsupported_oids_response(try_decoded), (
            "Returns all unsupported OIDs,not only certificate or algorithm related ones."
        )

    @staticmethod
    def _process_key_pair_param_req(entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process a key pair parameter request."""
        # GenMsg: {id-it 4}, OBJECT IDENTIFIER
        # GenRep: {id-it 4}, AlgorithmIdentifier | < absent >
        if not entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the key pair parameter request is not set.")

        _ = _try_decode_mock_ca(entry["infoValue"].asOctets(), univ.ObjectIdentifier())

        # We'll just return a dummy response for demonstration.
        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = rfc9480.id_it_keyPairParamReq
        return info_value, "This is just a dummy response for demonstration, The actual response is not implemented."

    def process_rev_passphrase(
        self, entry: rfc9480.InfoTypeAndValue, pki_message: PKIMessageTMP
    ) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process a revocation passphrase."""
        version = int(pki_message["header"]["pvno"])
        if not entry["infoValue"].isValue:
            raise BadRequest("The info value for the revocation passphrase is not set.")

        out, rest = try_decode_pyasn1(entry["infoValue"], rfc9480.EncryptedKey())  # type: ignore
        rest: bytes
        out: rfc9480.EncryptedKey
        if rest:
            raise BadAsn1Data("EncryptedKey")

        if out.getName() == "encryptedValue" and version == 3:
            raise BadRequest("The version is 3, but the encrypted value is a `EncryptedValue` structure.")

        if out.getName() == "envelopedData" and version != 3:
            raise BadRequest("The version is not 3, but the encrypted value is a `EnvelopedData` structure.")

        if out.getName() == "encryptedValue":
            raise NotImplementedError("The processing of the EncryptedValue is not implemented.")

        env_data = out["envelopedData"]
        passphrase = validate_enveloped_data(
            env_data=env_data,
            pki_message=pki_message,
            expected_raw_data=True,
            password=self.password,
            ee_key=self.prot_enc_key,
        )

        self.state.rev_passphrases.append(passphrase)

        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = rfc9480.id_it_revPassphrase
        return info_value, "Successfully processed the revocation passphrase."

    @staticmethod
    def process_supp_lang_tags(entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Return the supported language tags."""
        # The spec says in GenRep: "exactly 1" UTF8String giving the chosen language.
        # GenMsg: {id-it 16}, SEQUENCE SIZE (1..MAX) OF UTF8String
        # GenRep: {id-it 16}, SEQUENCE SIZE (1) OF UTF8String

        if not entry["infoValue"].isValue:
            raise BadRequest("The info value for the supported language tags is not set.")

        obj, rest = try_decode_pyasn1(entry["infoValue"], rfc9480.SuppLangTagsValue())  # type: ignore
        rest: bytes
        obj: rfc9480.SuppLangTagsValue

        if rest:
            raise BadAsn1Data("SuppLangTagsValue")

        if len(obj) == 0:
            raise BadRequest("The supported language tags are empty.")

        supp_langs = [x.prettyPrint() for x in obj]
        supp_langs = set(supp_langs)
        if len(supp_langs) == 0:
            raise BadRequest("The supported language tags are empty.")

        allowed_tags = ["en", "de", "fr"]
        for lang in supp_langs:
            if lang not in allowed_tags:
                raise BadRequest(f"The language tag {lang} is not supported.")

        # We'll pick "en" for demonstration.
        return prepare_supported_language_tags("en"), "Currently is always 'en' returned."

    def _process_ca_certs(self) -> Tuple[InfoTypeAndValue, str]:
        """Return the CA certificates."""
        # GenMsg: {id-it 17}, < absent >
        # GenRep: {id-it 17}, SEQUENCE SIZE (1..MAX) OF
        #                     CMPCertificate | < absent >
        info_value = rfc9480.InfoTypeAndValue()
        ca_cert_values = rfc9480.CaCertsValue()
        ca_cert_values.extend(self.ca_certs)
        info_value["infoType"] = rfc9480.id_it_caCerts
        info_value["infoValue"] = encoder.encode(ca_cert_values)
        return info_value, "Returns the CA certificates, may needs to be updated with all relevant certificates."

    def _process_root_ca_cert(self, entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, Optional[str]]:
        """Process the root CA certificate general message entry."""
        # GenMsg: {id-it 20}, RootCaCertValue | < absent >
        # GenRep: {id-it 18}, RootCaKeyUpdateValue | < absent >

        info_value = rfc9480.InfoTypeAndValue()
        if entry["infoValue"].isValue:
            root_val = _try_decode_mock_ca(entry["infoValue"].asOctets(), rfc9480.RootCaCertValue())
            root_val: rfc9480.CMPCertificate
            if not compare_pyasn1_objects(root_val, self.root_ca_cert):
                info_value["infoType"] = rfc9480.id_it_rootCaKeyUpdate
                return info_value, "The root CA certificate is not the same as the one in the Mock CA."

        key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        key = ensure_is_sign_key(key)

        info_value["infoType"] = rfc9480.id_it_rootCaKeyUpdate
        info_value["infoValue"] = prepare_new_root_ca_certificate(
            old_cert=self.root_ca_cert, old_priv_key=self.root_ca_key, new_priv_key=key, hash_alg="sha256"
        )
        return info_value, ("The root certificate in not actually updated,this is just a demonstration of the process.")

    def _process_cert_req_template(self) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Build the certificate request template.

        Build an InfoTypeAndValue containing a CertReqTemplateValue.
        In this example, we impose a required RSA key length of 2048 bits via 'keySpec'.
        - certTemplate is minimal and has the fields that MUST be absent left out
          (publicKey, serialNumber, signingAlg, issuerUID, subjectUID).
        """
        # GenMsg: {id-it 19}, < absent >
        # GenRep: {id-it 19}, CertReqTemplateContent | < absent >

        # 1. Prepare a minimal CertTemplate (all the fields that MUST be absent remain absent).
        cert_template = rfc9480.CertTemplate()
        # For example, you could add a subject or not:
        # cert_template['subject'] = some_rfc5280_Name if you want to require a subject.

        # 2. Create a Controls structure with an RSA key length requirement.
        controls = rfc9480.Controls()
        rsa_key_len_attr = rfc9480.AttributeTypeAndValue()
        rsa_key_len_attr["type"] = rfc9480.id_regCtrl_rsaKeyLen
        rsa_key_len_attr["value"] = rfc9480.RsaKeyLenCtrl(self.rsa_req_length)
        controls.append(rsa_key_len_attr)

        # If you want to enforce an allowed algorithm (e.g. Ed25519),
        # you can add an AlgIdCtrl here instead, for instance:
        #   alg_id_attr = rfc9480.AttributeTypeAndValue()
        #   alg_id_attr['type'] = rfc9480.id_regCtrl_algId
        #   alg_id_attr['value'] = <AlgIdCtrl structure>
        #   controls.append(alg_id_attr)

        # 3. Build the CertReqTemplateValue, assigning the CertTemplate and the keySpec controls.
        cert_req_template_val = rfc9480.CertReqTemplateValue()
        cert_req_template_val["certTemplate"] = cert_template
        cert_req_template_val["keySpec"] = controls

        # 4. Wrap it into an InfoTypeAndValue for id-it-certReqTemplate.
        info_val = rfc9480.InfoTypeAndValue()
        info_val["infoType"] = rfc9480.id_it_certReqTemplate
        info_val["infoValue"] = encoder.encode(cert_req_template_val)

        return info_val, "This is just a basic example of a certificate request template."

    def process_current_crl(self, entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process the current CRL."""
        # RFC4210 Section 5.3.19.6
        # GenMsg: {id-it 6}, < absent >
        # GenRep: {id-it 6}, CertificateList
        if entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the current CRL is set.")

        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = rfc9480.id_it_currentCRL
        crl = self.rev_handler.get_current_crl(self.root_ca_key, self.root_ca_cert)
        info_value["infoValue"] = crl
        return info_value, "This returns the current CRL of the Mock CA."

    def process_crl_update_retrieval(self, entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process the CRL update retrieval."""
        # GenMsg:    {id-it 22}, SEQUENCE SIZE (1..MAX) OF CRLStatus
        # GenRep:    {id-it 23}, SEQUENCE SIZE (1..MAX) OF
        #                            CertificateList  |  < absent >

        if not entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the CRL status list is not set.")

        crl_status_list = _try_decode_mock_ca(entry["infoValue"].asOctets(), CRLStatusListValueAsn1())

        if len(crl_status_list) == 0:
            raise BadValueBehavior("The CRL status list is empty.")

        out_crls = []
        texts = []
        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = rfc9480.id_it_crls

        crl_status_list: List[CRLStatusAsn1]
        for i, crl_status in enumerate(crl_status_list):
            data, text = self._process_crl_status(crl_status, i)
            if data:
                out_crls.append(data)

        if out_crls:
            data = set(out_crls)
            out = univ.SequenceOf()
            for x in data:
                tmp_list = _try_decode_mock_ca(x, rfc5280.CertificateList())  # type: ignore
                tmp_list: rfc5280.CertificateList
                out.append(tmp_list)

            der_data = encoder.encode(out)
            info_value["infoValue"] = der_data
            return info_value, "\n".join(texts)

        return info_value, "The CRL status list is up to date."

    def _pretty_print_general_names(self, general_names: rfc9480.GeneralNames) -> str:
        """Pretty print the general names."""
        data = "GeneralNames: "
        for i, entry in enumerate(general_names):
            entry: rfc9480.GeneralName
            if entry in ["uniformResourceIdentifier", "rfc822Name"]:
                data += f"At index: {i} {entry.prettyPrint()}, \n"
            elif entry.getName() == "directoryName":
                data += f"At index: {i} {entry['directoryName'].prettyPrint()}, \n"
            else:
                data += f"At index: {i} {entry.getName()}, {entry[entry.getName()].prettyPrint()} \n"

        return data

    def _process_crl_status(self, crl_status: CRLStatusAsn1, index: int) -> Tuple[Optional[bytes], Optional[str]]:
        """Process the CRL status."""
        # TODO add a github issue for this structure.
        source = crl_status["source"]
        source: CRLSourceAsn1
        time = crl_status["thisUpdate"]

        text = None

        root_ca_name = self.root_ca_cert["tbsCertificate"]["subject"]

        if not time.isValue:
            pass

        if source.getName() == "issuer":
            issuer: rfc9480.GeneralNames = source["issuer"]
            result = find_name_inside_general_names(issuer, root_ca_name)
            if not result:
                issuer_name = get_openssl_name_notation(source["issuer"])
                text = f"The issuer is not the root CA. Got: {issuer_name}, at index: {index}."

        elif source.getName() == "dpn":
            dnp: rfc9480.DistributionPointName = source["dpn"]
            if dnp.getName() == "fullName":
                issuer: rfc9480.GeneralNames = dnp["fullName"]
                result = find_name_inside_general_names(issuer, root_ca_name, self.crl_url)
                if not result:
                    issuer_name = self._pretty_print_general_names(source["issuer"])
                    text = (
                        f"The issuer inside the `DPN` is not the root CA or the CRL URL."
                        f" Got: {issuer_name}, at index: {index}."
                    )

            elif dnp.getName() == "nameRelativeToCRLIssuer":
                name: rfc5280.RelativeDistinguishedName = dnp["nameRelativeToCRLIssuer"]
                result = find_rel_dis_name_in_name(rdn=name, name=root_ca_name)
                if not result:
                    text = f"The issuer inside the `DPN` is not the root CA. Got: {name}, at index: {index}."

            else:
                # This means that the structure was updated.
                raise NotImplementedError(
                    f"The processing of the DPN structure is not implemented.: Got: {dnp.getName()}"
                )

        else:
            # This means that the structure was updated.
            raise NotImplementedError(f"The processing of the CRL source is not implemented.Got: {source.getName()}")

        if text is not None:
            return None, text

        if not time.isValue:
            return self.rev_handler.get_current_crl(self.root_ca_key, self.root_ca_cert), text

        time_obj = pyasn1_time_obj_to_py_datetime(time)
        if (datetime.now(timezone.utc) - time_obj).total_seconds() > 90000:
            return self.rev_handler.get_current_crl(self.root_ca_key, self.root_ca_cert), None

        return None, "The CRL is up to date, more than 90000 seconds is old."

    @staticmethod
    def process_preferred_sym_alg(entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Return the preferred symmetric algorithm."""
        # GenMsg: {id-it 4}, < absent >
        # GenRep: {id-it 4}, AlgorithmIdentifier

        if entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the preferred symmetric algorithm is set.")
        alg_id = rfc9480.AlgorithmIdentifier()
        # Is also the one used for the deprecated `EncryptedValue` structure.
        alg_id["algorithm"] = rfc9481.id_aes256_CBC
        alg_id["parameters"] = rfc3565.AES_IV(b"A" * 16)
        out = rfc9480.InfoTypeAndValue()
        out["infoType"] = rfc9480.id_it_preferredSymmAlg
        out["infoValue"] = encoder.encode(alg_id)
        return out, "Currently, the preferred symmetric algorithm is AES-256-CBC."

    @staticmethod
    def process_enc_key_pair_types(entry: rfc9480.InfoTypeAndValue) -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Process the encryption key pair types."""
        #  GenMsg: {id-it 3}, < absent >
        #  GenRep: {id-it 3}, SEQUENCE SIZE (1..MAX) OF
        #                           AlgorithmIdentifier
        if entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the encryption key pair types is set.")

        alg_ids = AlgorithmIdentifiers()
        alg_ids_list = get_all_supported_ecc_alg_ids()
        alg_ids_list += [prepare_alg_id("x25519"), prepare_alg_id("x448")]
        alg_ids.extend(alg_ids_list)
        return cmputils.prepare_info_type_and_value(
            rfc9480.id_it_encKeyPairTypes, alg_ids
        ), "Supports a lot of key types."

    def _process_ca_prot_enc_cert(self, entry: rfc9480.InfoTypeAndValue) -> Tuple[InfoTypeAndValue, str]:
        """Can be used by an EE to get the CA protocol encryption certificate.

        To securely exchange sensitive information with the CA.
        """
        # GenMsg: {id-it 1}, < absent >
        # GenRep: {id-it 1}, CMPCertificate | < absent >
        if entry["infoValue"].isValue:
            raise BadValueBehavior("The info value for the CA protocol encryption certificate is set.")

        out = rfc9480.InfoTypeAndValue()
        out["infoType"] = rfc9480.id_it_caProtEncCert
        # Must be a single CMPCertificate
        if self.prot_enc_cert is None:
            raise ValueError("The protocol encryption certificate is not set.")
        out["infoValue"] = self.prot_enc_cert
        self.add_env_data_certs = True
        return out, (
            "All other certificates which are wished to be used by the EE are inside the extraCerts,"
            "filed of the PKIMessage."
        )

    @staticmethod
    def _process_sign_key_pair_types() -> Tuple[rfc9480.InfoTypeAndValue, str]:
        """Return all supported signature algorithm identifiers."""
        # This MAY be used by the EE to get the list of signature algorithm whose subject
        # public key values the CA is willing to certify.
        # GenMsg: {id-it 2}, < absent >
        # GenRep: {id-it 2}, SEQUENCE SIZE (1..MAX) OF
        #                     AlgorithmIdentifier
        info_value = rfc9480.InfoTypeAndValue()
        info_value["infoType"] = rfc9480.id_it_signKeyPairTypes
        ids = [prepare_alg_id("rsa"), prepare_alg_id("ed25519"), prepare_alg_id("ed448")]

        ids += get_all_supported_ecc_alg_ids()
        alg_ids = AlgorithmIdentifiers()

        for oid in PQ_SIG_OID_2_NAME:
            alg_id = rfc9480.AlgorithmIdentifier()
            alg_id["algorithm"] = oid
            alg_ids.append(alg_id)

        for oid in HYBRID_SIG_OID_2_NAME:
            alg_id = rfc9480.AlgorithmIdentifier()
            alg_id["algorithm"] = oid
            alg_ids.append(alg_id)

        alg_ids.extend(ids)

        info_value["infoValue"] = encoder.encode(alg_ids)
        return info_value, (
            "The supported signature algorithm identifiers are returned."
            "If a algorithm is not supported, this either means "
            "that it is nit supported or that the `HYBRID_SIG_OID_2_NAME`"
            "or `PQ_SIG_OID_2_NAME` is not updated."
        )

    def _process_kem_ciphertext_info(
        self, entry: rfc9480.InfoTypeAndValue, pki_message: PKIMessageTMP
    ) -> rfc9480.InfoTypeAndValue:
        """Process the KEM ciphertext info."""
        # GenMsg: {id-it TBD1}, < absent >
        # GenRep: {id-it TBD1}, KemCiphertextInfo

        if entry["infoValue"].isValue:
            raise BadRequest("The info value for the KEM ciphertext info is set.")

        cert = pki_message["extraCerts"][0]

        if not cert.isValue:
            raise BadRequest("The `certificate` for the KemCiphertextInfo is not set.")

        public_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

        public_key = ensure_is_kem_pub_key(public_key)
        ss, info_val = _prepare_kem_ct_info(  # type: ignore
            public_key,
        )
        ss: bytes
        self.add_shared_secert(ss, pki_message)
        return info_val

    def add_shared_secert(self, ss: bytes, pki_message: PKIMessageTMP) -> None:
        """Add the shared secret, for the transaction ID."""
        tx_id = pki_message["header"]["transactionID"].asOctets()
        self.state.shared_secrets[tx_id] = ss

    def remove_shared_secert(self, pki_message: PKIMessageTMP) -> bool:
        """Remove the shared secret, for the transaction ID."""
        tx_id = pki_message["header"]["transactionID"].asOctets()
        if tx_id in self.state.shared_secrets:
            del self.state.shared_secrets[tx_id]
            return True

        logging.warning("The shared secret was not found, for the transaction ID: %s", tx_id)
        return False
