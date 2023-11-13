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