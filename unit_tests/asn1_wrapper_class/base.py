# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from abc import abstractmethod
from dataclasses import dataclass, fields

import pyasn1.type.base


@dataclass
class Asn1Wrapper:
    """A base class for ASN.1 object wrapping with dictionary-like access."""

    @abstractmethod
    def encode(self) -> bytes:
        """Encodes the object."""
        pass

    @classmethod
    def from_der(cls, data: bytes) -> bytes:
        """Load a object from DER encoded data."""
        pass

    @abstractmethod
    def from_pyasn1(self, data: bytes) -> "Asn1Wrapper":
        """Load an object from `pyasn1` object"""
        pass

    @staticmethod
    def get_size(data: bytes):
        size = len(data)
        if size < 128:
            size_encoded = size.to_bytes(1, byteorder="big")
        else:
            size_length = (size.bit_length() + 7) // 8
            size_encoded = (0x80 | size_length).to_bytes(1, byteorder="big") + size.to_bytes(size_length, byteorder="big")

        return b"\x30" + size_encoded + data

    def __getitem__(self, key):
        """Get an item by ASN.1 key."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"Key '{key}' not found.")

    def __setitem__(self, key, value):
        """Set an item by ASN.1 key."""
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(f"Key '{key}' not found.")

    def __delitem__(self, key):
        """Delete an item by setting it to None."""
        if hasattr(self, key):
            setattr(self, key, None)
        else:
            raise KeyError(f"Key '{key}' not found.")

    def _process_val(self, value, indent_level=1) -> str:
        """Process the value for the representation with support for offsets."""
        if isinstance(value, Asn1Wrapper):
            return self._repr_nested(value, indent_level)

        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, list):
            return ",".join(value)

        elif value is None:
            value = ""

        elif isinstance(value, pyasn1.type.base.Asn1Type):
            return value.prettyPrint() # type: ignore

        return value

    def _repr_nested(self, obj, indent_level: int) -> str:
        """Recursively represent a nested Asn1Wrapper object."""
        repr_str = ""

        repr_str += f"{obj.__class__.__name__}:\n"

        for field in fields(obj):
            value = getattr(obj, field.name, None)
            repr_str += f"{' ' * (4 * (indent_level + 1))}{field.name}={self._process_val(value, indent_level + 1)}\n"

        return repr_str

    def __repr__(self):
        """Generate a string representation of the object."""
        repr_str = f"{self.__class__.__name__}:\n"

        for field in fields(self):
            value = getattr(self, field.name, None)
            repr_str += f"{' ' * 4}{field.name}={self._process_val(value, 1)}\n"

        return repr_str

    def __eq__(self, other):
        """Equality check between two Asn1Wrapper objects."""
        if not isinstance(other, self.__class__):
            return False
        return all(
            getattr(self, field.name, None) == getattr(other, field.name, None)
            for field in fields(self)
        )

    def isValue(self) -> bool:
        """Check if any field is set.

        :return: `True` if any field is set; Otherwise `False`.
        """
        return any(getattr(self, field) for field in fields(self))
