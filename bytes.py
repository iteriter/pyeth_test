import binascii


def bytes2int(p: bytes) -> int:
    """
    Take a byte sequence, interpret as unsigned binary number, most significant byte first. Return integer.
    """
    return int.from_bytes(bytes=p, byteorder="big", signed=False)


def int2bytes(x: int):
    """
    Take integer, convert into byte sequence
    """
    bit_len = 0
    x_copy = x
    while x_copy > 0:
        x_copy >>= 1
        bit_len += 1
    h = hex(x)[2:]
    # fix odd length conversion problem
    if len(h) % 2 == 1:
        h = '0' + h
    return binascii.unhexlify(h)