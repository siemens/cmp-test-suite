from base64 import b64decode


def modify_bytes(data, offset=0, patch=b'0'):
    """Manipulate a raw payload to change some bytes in it
    
    :param data: bytes, original buffer to modify
    :param offset: int, location where to modify bytes
    :param patch: optional bytes, what data to include at that offset; by default will set a byte to 0
    """
    return data[:offset] + patch + data[offset+len(patch):]


def buffer_length_must_be_at_least(data, length):
    """Check whether the length of a byte buffer is at least `length` bytes

    :param data: bytes, the buffer to examine
    :param length: int, the minimum required length in bytes
    :returns: bool
    """
    if not len(data) >= length:
        raise ValueError(f"Buffer length {len(data)} < {length}, but should have been >={length}!")


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


if __name__ == "__main__":
    print (load_and_decode_pem_file('../data/1.3.6.1.4.1.2.267.7.4.4-dilithium2/csr.pem'))