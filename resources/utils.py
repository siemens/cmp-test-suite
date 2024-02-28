from base64 import b64decode, b64encode
import re
import logging
from pyasn1.type import base


def log_asn1(pyasn1_obj):
    """Log a pyasn1 object as a string for debugging purposes. For convenience, it will gracefully
    ignore objects that are not pyasn1, so that the function can be invoked from RobotFramework
    scenarios without having to check the type of the object first.
    """
    if isinstance(pyasn1_obj, base.Asn1Item):
        logging.info(pyasn1_obj.prettyPrint())
    else:
        logging.info("Cannot prettyPrint this, it is not a pyasn1 object")


def log_base64(data):
    """Log some data as a base64 encoded string, this is useful for binary payloads"""
    if type(data) is bytes:
        logging.info(b64encode(data))
    elif type(data) is str:
        logging.info(b64encode(data.encode('ascii')))


def manipulate_first_byte(data):
    """Manipulate a buffer to change its first byte to 0x00 (or to 0x01 if it was 0x00).

    This is useful if you want to deliberately break a cryptographic signature.
    
    :param data: bytes, buffer to modify
    :returns: bytes, modified buffer
    """
    if data[0] == 0:
        return b'\x01' + data[1:]
    else:
        return b'\x00' + data[1:]


def buffer_length_must_be_at_least(data, length):
    """Check whether the length of a byte buffer is at least `length` bytes

    :param data: bytes, the buffer to examine
    :param length: stringified int, the minimum required length in bytes; it will come as a string
                   from RobotFramework, just as a matter of convenience of the caller.
    :returns: bool
    """
    if not len(data) >= int(length):
        raise ValueError(f"Buffer length {len(data)} < {length}, but should have been >={length} bytes!")


def decode_pem_string(data):
    if type(data) is bytes:
        data = data.decode('ascii')
    raw = data.splitlines()
    filtered_lines = []
    # first do some cosmetic filtering
    for line in raw:
        if line.startswith('#'):  # remove comments
            continue
        elif line.strip() == '':  # remove blank lines
            continue
        else:
            filtered_lines.append(line)

    if '-----BEGIN' in filtered_lines[0]:
        result = ''.join(filtered_lines[1:-1])
    else:
        result = ''.join(filtered_lines)

    # note that b64decode doesn't care about \n in the string to be decoded, so we keep them to potentially improve
    # readability when debugging.
    return b64decode(result)

def load_and_decode_pem_file(path):
    """Load a base64-encoded PEM file, with or without a header, ignore comments, and return the decoded data.

    This is an augmented version of the PEM format, which allows one to add comments to the file, by starting the
    line with a # character. This is purely a convenience for the user, and is not part of the standard.

    :param path: str, path to the file you want to load
    :returns: bytes, the data loaded from the file.
    """
    # normally it should always have a header/trailer (aka "armour"), but we'll be tolerant to that.

    filtered_lines = []
    with open(path, 'r') as f:
        raw = f.readlines()
        # first do some cosmetic filtering
        for line in raw:
            if line.startswith('#'):  # remove comments
                continue
            elif line.strip() == '':  # remove blank lines
                continue
            else:
                filtered_lines.append(line)

    if '-----BEGIN' in filtered_lines[0]:
        result = ''.join(filtered_lines[1:-1])
    else:
        result = ''.join(filtered_lines)

    # note that b64decode doesn't care about \n in the string to be decoded, so we keep them to potentially improve
    # readability when debugging.
    return b64decode(result)


def strip_armour(raw):
    """Remove PEM armour, like -----BEGIN CERTIFICATE REQUEST----- and -----END CERTIFICATE REQUEST-----

    :param raw: bytes, input structure
    :returns: bytes unarmoured data
    """
    result = raw.decode('ascii')
    result = re.sub("-----BEGIN .*?-----", '', result)
    result = re.sub("-----END .*?-----", '', result)
    result = result.replace("\n", "")
    return bytes(result, 'ascii')


if __name__ == "__main__":
    print (load_and_decode_pem_file('../data/1.3.6.1.4.1.2.267.7.4.4-dilithium2/csr.pem'))