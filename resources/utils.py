import logging
import re
from base64 import b64decode, b64encode
from collections import Counter
from itertools import combinations

from pyasn1.type import base


def nonces_must_be_diverse(nonces, minimal_hamming_distance=10):
    """Check that a list of nonces are diverse enough, by computing the Hamming distance between them. Nonces will be
    right-padded with 0x00 if their lengths are different.

    :param nonces: list of bytes, nonces to check
    :param minimal_hamming_distance: stringified int, the minimum hamming distance between any two nonces; stringified
                                     for convenience of calling from within RobotFramework tests.
    :returns: nothing, but will raise a ValueError if at least two nonces are not diverse enough; the checker stops at
              the first violation it finds.
    """
    for nonce1, nonce2 in combinations(nonces, 2):
        # Pad the shorter nonce with zeros, so they are of the same length
        max_length = max(len(nonce1), len(nonce2))
        nonce1 = nonce1.ljust(max_length, b'\x00')
        nonce2 = nonce2.ljust(max_length, b'\x00')

        hamming_distance = sum([bin(n1 ^ n2).count('1') for n1, n2 in zip(nonce1, nonce2)])
        if hamming_distance < minimal_hamming_distance:
            report = (f"Nonces are not diverse enough! Hamming distance between nonces {nonce1} and {nonce2} is "
                      f"{hamming_distance}, but should have been at least {minimal_hamming_distance}.")

            # Convert bytes to binary strings, as it is an easier representation for humans to look at
            nonce1_bin = ' '.join([format(n, '08b') for n in nonce1])
            nonce2_bin = ' '.join([format(n, '08b') for n in nonce2])
            report += f"\nNonce1: {nonce1_bin}\nNonce2: {nonce2_bin}"
            raise ValueError(report)


def nonces_must_be_unique(nonces):
    """Check that a list of nonces are all unique.

    :param nonces: list of bytes, nonces to check
    :returns: nothing, but will raise a ValueError if the nonces are not unique
    """
    # uncomment this to provoke an error by duplicating a nonce
    # nonces.append(nonces[0])
    nonce_counts = Counter(nonces)
    repeated_nonces = [(nonce, count) for nonce, count in nonce_counts.items() if count > 1]

    if repeated_nonces:
        raise ValueError(f"Nonces are not unique! Repeated nonces with counts: {repeated_nonces}")


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


def log_data_type(data):
    logging.info(type(data))


def log_args(*args):
    """
    Log a message by replacing placeholders in a base string with provided arguments.

    This keyword allows you to log a formatted message by replacing placeholders
    (indicated by asterisks `*`) in a base string with the subsequent arguments
    provided. The asterisks in the base string act as placeholders, which are
    replaced one by one with the arguments supplied.

    Example use case:
    - Input: `log_args("This is the type: *", "class: int")`
    - Output: The logged message would be: `"This is the type: class: int"`

    If the base string does not contain any placeholders, the arguments are appended
    to the base string.

    Arguments:
    - *args: The first argument is the base string, and the following arguments are
             the values that will replace the placeholders in the base string.

    Returns:
    - None. The function logs the formatted message.
    """

    if isinstance(args[0], str):
        base = args[0]
        for arg in args[1:]:
            if "*" in base and not "*x":
                # Replace the first occurrence of the placeholder '*' with the next argument
                base = base.replace("*", str(arg), 1)
            else:
                # If no placeholders are left, append the argument to the base string
                base += str(arg)
    else:
        # If the first argument is not a string, join all arguments into a single string
        base = " ".join(args)

    # Log the final message after formatting
    logging.info(base.strip())




if __name__ == "__main__":
    print(load_and_decode_pem_file('../data/1.3.6.1.4.1.2.267.7.4.4-dilithium2/csr.pem'))
