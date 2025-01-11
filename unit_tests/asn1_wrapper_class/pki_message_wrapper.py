# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Union

from cryptography import x509
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, constraint, tag, univ, useful
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import rfc9480
from resources.protectionutils import protect_pkimessage
from robot.api.deco import not_keyword

from unit_tests.asn1_wrapper_class.base import Asn1Wrapper
from unit_tests.asn1_wrapper_class.wrapper_alg_id import AlgorithmIdentifier


def _prepare_bytes_field(value: bytes, tag_number: int) -> univ.OctetString:
    return univ.OctetString(value).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_number))


@dataclass
class GeneralInfoEntry(Asn1Wrapper):
    """Represents a single entry in the generalInfo field."""

    infoType: str
    infoValue: Union[str, datetime, None]

@dataclass
class GeneralInfo(Asn1Wrapper):
    """Dataclass wrapper for the generalInfo field."""

    data: List[GeneralInfoEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Union[str, datetime, None]]:
        """Convert the generalInfo entries into a dictionary without prefixes."""
        return {entry.infoType: entry.infoValue for entry in self.data}

    @classmethod
    def from_dict(cls, info_dict: Dict[str, Union[str, datetime, None]]) -> "GeneralInfo":
        """Create a GeneralInfo instance from a dictionary."""
        entries = [GeneralInfoEntry(infoType=key, infoValue=value) for key, value in info_dict.items()]
        return cls(data=entries)

    def to_asn1(self) -> univ.SequenceOf:
        """Convert the GeneralInfo to its ASN.1 representation."""
        general_info_wrapper = (
            univ.SequenceOf(componentType=rfc9480.InfoTypeAndValue()) # type: ignore
            .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX))
            .subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))
        )

        for entry in self.data:
            info_type_and_value = rfc9480.InfoTypeAndValue()
            info_type_and_value["infoType"] = getattr(rfc9480, f"id_it_{entry.infoType}")

            if isinstance(entry.infoValue, str):
                info_type_and_value["infoValue"] = char.UTF8String(entry.infoValue)
            elif isinstance(entry.infoValue, datetime):
                info_type_and_value["infoValue"] = useful.GeneralizedTime(entry.infoValue.strftime("%Y%m%d%H%M%SZ"))
            else:
                info_type_and_value["infoValue"] = univ.Null("")  # Default to Null if no value is provided

            general_info_wrapper.append(info_type_and_value)

        return general_info_wrapper

    @classmethod
    def from_asn1(cls, asn1_data: univ.SequenceOf) -> "GeneralInfo":
        """Create a GeneralInfo instance from ASN.1 data."""
        entries = []
        for item in asn1_data:

            if item["infoType"] == rfc9480.id_it_implicitConfirm:
                info_type = "implicitConfirm"
                info_value = item["infoValue"].asOctets()

            elif item["infoType"] == rfc9480.id_it_confirmWaitTime:
                info_type = "confirmWaitTime"
                info_value, _ = decoder.decode(item["infoValue"], useful.GeneralizedTime())

            elif item["infoType"] == rfc9480.id_it_certReqTemplate:
                info_type = "certReqTemplate"
                info_value, _ = decoder.decode(item["infoValue"], char.UTF8String())
                info_value = str(info_value)
            else:
                info_type = str(item["infoValue"])
                info_value = item["infoValue"].asOctets()
            entries.append(GeneralInfoEntry(infoType=info_type, infoValue=info_value))
        return cls(data=entries)

    def __len__(self) -> int:
        """Return the number of entries."""
        return len(self.data)

    def add(self, info_type: str, info_value: Union[str, datetime, None]) -> None:
        """Add a new entry to the generalInfo field."""
        self.data.append(GeneralInfoEntry(infoType=info_type, infoValue=info_value))

    def contains(self, info_type: str) -> bool:
        """Check if an entry with the specified info_type exists."""
        return any(entry.infoType == info_type for entry in self.data)

    def get(self, info_type: str) -> Optional[GeneralInfoEntry]:
        """Retrieve an entry by info_type."""
        for entry in self.data:
            if entry.infoType == info_type:
                return entry
        return None


@not_keyword
def prepare_name(
        common_name: str, implicit_tag_id: Optional[int] = None, name: Optional[rfc9480.Name] = None
) -> rfc9480.Name:
    """Prepare a `rfc9480.Name` object or fill a provided object.

    :param common_name: Common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,CN=Joe Mustermann"
    :param implicit_tag_id: the implicitTag id for the new object.
    :param name: An optional `pyasn1` Name object in which the data is parsed. Else creates a new object.
    :return: The filled object.
    """
    name_obj = x509.Name.from_rfc4514_string(common_name)
    der_data = name_obj.public_bytes()

    if name is None:
        if implicit_tag_id is not None:
            name = rfc9480.Name().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, implicit_tag_id)
            )

    name_tmp, rest = decoder.decode(der_data, rfc9480.Name())
    if rest != b"":
        raise ValueError("The decoding of `Name` structure had a remainder!")

    if name is None:
        return name_tmp

    name["rdnSequence"] = name_tmp["rdnSequence"]
    return name

@not_keyword
def prepare_general_name(name_type: str, name_str: str) -> rfc9480.GeneralName:
    """Prepare a `pyasn1` GeneralName object used by the `PKIHeader` structure.

    :param name_type: The type of name to prepare, e.g., "directoryName" or "rfc822Name" or
    "uniformResourceIdentifier".
    :param name_str: The actual name string to encode in the GeneralName.
    In OpenSSL notation, e.g., "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann".
    :return: A `GeneralName` object with the encoded name based on the provided `name_type`.
    """
    if name_type == "directoryName":
        name_obj = prepare_name(name_str, 4)
        general_name = rfc9480.GeneralName()
        return general_name.setComponentByName("directoryName", name_obj)

    if name_type == "rfc822Name":
        return rfc9480.GeneralName().setComponentByName("rfc822Name", name_str)

    if name_type == "uniformResourceIdentifier":
        return rfc9480.GeneralName().setComponentByName("uniformResourceIdentifier", name_str)

    raise NotImplementedError(f"GeneralName name_type is Unsupported: {name_type}")


def _decode_general_name(sender, recipient):

    if sender.isValue:
        sender_type = sender.getName()
        sender = str(sender[sender_type])
    else:
        sender = None
        sender_type = None

    if recipient.isValue:
        recipient_type = recipient.getName()
        recipient = str(recipient[recipient_type])
    else:
        recipient = None
        recipient_type = None

    return sender, sender_type, recipient, recipient_type


@dataclass
class PKIHeader(Asn1Wrapper):
    pvno: Optional[int] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    messageTime: Optional[datetime] = None
    protectionAlg: Optional[AlgorithmIdentifier] = None
    senderKID: Optional[bytes] = None
    recipKID: Optional[bytes] = None
    transactionID: Optional[bytes] = None
    senderNonce: Optional[bytes] = None
    recipNonce: Optional[bytes] = None
    freeText: Optional[List[str]] = None
    generalInfo: Optional[GeneralInfo] = None
    _recip_type: str = "rfc822Name"
    _sender_type: str = "rfc822Name"


    def to_asn1(self, omit_fields: Optional[List[str]] = None) -> rfc9480.PKIHeader:
        omit_fields = set(omit_fields or [])
        pki_header_asn1 = rfc9480.PKIHeader()

        if "pvno" not in omit_fields and self.pvno is not None:
            pki_header_asn1["pvno"] = univ.Integer(self.pvno)

        if "sender" not in omit_fields and self.sender is not None:
            pki_header_asn1["sender"] = prepare_general_name(self._sender_type, self.sender)

        if "recipient" not in omit_fields and self.recipient is not None:
            pki_header_asn1["recipient"] = prepare_general_name(self._recip_type, self.recipient)

        if "message_time" not in omit_fields and self.messageTime is not None:
            pki_header_asn1["messageTime"] = useful.GeneralizedTime.fromDateTime(self.messageTime).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

        if "protection_alg" not in omit_fields and self.protectionAlg is not None:

            obj, rest = decoder.decode(self.protectionAlg.encode(), rfc9480.AlgorithmIdentifier())

            obj = obj.subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
            )
            pki_header_asn1["protectionAlg"] = obj

        if "sender_kid" not in omit_fields and self.senderKID is not None:
            pki_header_asn1["senderKID"] = _prepare_bytes_field(self.senderKID, 2)

        if "recip_kid" not in omit_fields and self.recipKID is not None:
            pki_header_asn1["recipKID"] = _prepare_bytes_field(self.recipKID, 3)

        if "transaction_id" not in omit_fields and self.transactionID is not None:
            pki_header_asn1["transactionID"] = _prepare_bytes_field(self.transactionID, 4)

        if "sender_nonce" not in omit_fields and self.senderNonce is not None:
            pki_header_asn1["senderNonce"] = _prepare_bytes_field(self.senderNonce, 5)

        if "recip_nonce" not in omit_fields and self.recipNonce is not None:
            pki_header_asn1["recipNonce"] = _prepare_bytes_field(self.recipNonce, 6)

        if "free_text" not in omit_fields and self.freeText is not None:
            pki_free_text = rfc9480.PKIFreeText().subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 7))
            pki_header_asn1["freeText"] = pki_free_text
            for text in self.freeText:
                pki_header_asn1["freeText"].append(char.UTF8String(text))

        if "general_info" not in omit_fields and self.generalInfo is not None:
            self.generalInfo.to_asn1()
            pki_header_asn1["generalInfo"] = self.generalInfo.to_asn1()

        return pki_header_asn1

    def encode(self, omit_fields: Optional[List[str]] = None) -> bytes:
        return encoder.encode(self.to_asn1(omit_fields=omit_fields))

    @classmethod
    def from_asn1(cls, pki_header_asn1: rfc9480.PKIHeader) -> "PKIHeader":
        pvno = int(pki_header_asn1["pvno"]) if pki_header_asn1["pvno"].isValue else None

        sender, sender_type, recipient, recipient_type = _decode_general_name(
            pki_header_asn1["sender"],
            pki_header_asn1["recipient"],
        )

        message_time = (
            pki_header_asn1["messageTime"].asDateTime if pki_header_asn1["messageTime"].isValue else None
        )
        protection_alg = (
            AlgorithmIdentifier.from_alg_id(pki_header_asn1["protectionAlg"])
            if pki_header_asn1["protectionAlg"].isValue
            else None
        )
        sender_kid = bytes(pki_header_asn1["senderKID"]) if pki_header_asn1["senderKID"].isValue else None
        recip_kid = bytes(pki_header_asn1["recipKID"]) if pki_header_asn1["recipKID"].isValue else None
        transaction_id = bytes(pki_header_asn1["transactionID"]) if pki_header_asn1["transactionID"].isValue else None
        sender_nonce = bytes(pki_header_asn1["senderNonce"]) if pki_header_asn1["senderNonce"].isValue else None
        recip_nonce = bytes(pki_header_asn1["recipNonce"]) if pki_header_asn1["recipNonce"].isValue else None
        free_texts = None
        if pki_header_asn1["freeText"].isValue:
            free_texts = [str(x) for x in pki_header_asn1["freeText"]]

        if pki_header_asn1["generalInfo"].isValue:
            raise NotImplementedError("Decoding general_info is not implemented")

        return cls(
            pvno=pvno,
            sender=sender,
            recipient=recipient,
            messageTime=message_time,
            protectionAlg=protection_alg,
            senderKID=sender_kid,
            recipKID=recip_kid,
            freeText=free_texts,
            transactionID=transaction_id,
            senderNonce=sender_nonce,
            recipNonce=recip_nonce,
            _sender_type=sender_type,
            _recip_type=recipient_type,
        )

    @classmethod
    def decode(cls, data: bytes) -> "PKIHeader":
        pki_header_asn1, _ = decoder.decode(data, asn1Spec=rfc9480.PKIHeader())
        return cls.from_asn1(pki_header_asn1)


    def patch_for_exchange(
            self,
            messageTime: bool = True,
            transactionID: bool = True,
            senderNonce: bool = True,
    ):
        """Update PKIHeader fields for exchange based on the provided arguments.

        :param messageTime: A flag whether to set `messageTime` to the current UTC time.
        :param transactionID:  A flag whether to generate a random `transactionID`.
        :param senderNonce:  A flag whether to generate a random `senderNonce`.
        """
        if messageTime:
            self.messageTime = datetime.now()

        if transactionID:
            self.transactionID = os.urandom(16)

        if senderNonce:
            self.senderNonce = os.urandom(16)



@dataclass
class PKIBody:
    data: rfc9480.PKIBody

    def getName(self):
        return self.data.getName()

    def encode(self) -> bytes:
        return encoder.encode(self.data)


@dataclass
class PKIMessage(Asn1Wrapper):
    header: PKIHeader
    body: PKIBody
    protection: Optional[bytes] = None
    extraCerts: Optional[List[rfc9480.CMPCertificate]] = field(default_factory=list)
    _private_key = None

    def patch_cert_reques(self):
        raise NotImplementedError()

    @staticmethod
    def from_der(data: bytes, exclude_body: bool = False) -> "PKIMessage":
        header = PKIHeader()
        extra_certs = []
        protection = None

        data, rest = decoder.decode(data, rfc9480.PKIHeader())
        header.from_der(data)

        obj, rest = decoder.decode(rest, univ.Sequence())

        if rest:
           raise NotImplementedError()

        return PKIMessage(header=header, body=obj, extra_certs=extra_certs, protection=protection)



    def set_private_key(self, private_key) -> None:
        """Set the private key for this PKIMessage.

        :param private_key: The private key to use.
        :return:
        """
        self._private_key = private_key

    def patch_header(self, omit_field: str):
        raise NotImplementedError()

    def encode(self) -> bytes:
        """Encode the PKIMessage as a DER byte sequence.

        :return: DER-encoded PKIMessage.
        """
        data = b""
        if self.header:
            data += self.header.encode()

        if self.body:
            data += self.body.encode()

        if self.protection:
            wrapped_protection = (
                rfc9480.PKIProtection()
                .fromOctetString(self.protection)
                .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))
            )
            data += encoder.encode(wrapped_protection)

        if self.extraCerts:
            extra_certs_wrapper: univ.SequenceOf = (
                univ.SequenceOf(componentType=rfc9480.CMPCertificate())  # type: ignore
                .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX))
                .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 1))
            )

            extra_certs_wrapper.extend(self.extraCerts)
            data += encoder.encode(extra_certs_wrapper)

        return data

    def patch_for_exchange(self, private_key=None,
                           password: str = None,
                           messageTime: bool = True,
                           transactionID: bool = True,
                           senderNonce: bool = True,
                           ) -> bytes:
        """Update PKIMessage fields for exchange based on the provided arguments.

        :param private_key:
        :param password:
        :param messageTime:
        :param transactionID:
        :param senderNonce:
        :return:
        """
        self.header.patch_for_exchange(
            messageTime=messageTime,
            transactionID=transactionID,
            senderNonce=senderNonce
        )

        self.protect(password=password, private_key=private_key or self._private_key)

        return self.encode()


    def protect(self,
                password: Optional[str] = None,
                private_key=None,
                protection: Optional[str] = None,
                **params):
        """Protect this PKIMessage using the provided password or private_key.

        :param password: The password to protect the PKIMessage with.
        :param private_key: The private key to sign the PKIMessage with.
        :param protection: The protection methode as string to use.
        :return: The DER-encoded updated PKIMessage.
        """
        if not password or not private_key or not self._private_key:
            raise ValueError("Password or private_key is required")


        protection = protection or ("signature" if private_key or self._private_key else None)
        pki_message = protect_pkimessage(pki_message=self,
                                         protection=protection,
                                         password=password,
                                         private_key=private_key
                                         **params)

        return encoder.encode(pki_message)

