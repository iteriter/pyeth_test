import binascii

def byte_mod(byte_a, byte_b):
    """Take two byte sequences representing unsigned integers a,b with MSB on the left
    Return a mod b in byte sequence form"""
    mod = int.from_bytes(byte_a, 'big', signed=False) % int.from_bytes(byte_b, 'big', signed=False)
    return bytes.fromhex(hex(mod)[2:])


def bytes2int(p: bytes) -> int:
    """Take a byte sequence, interpret as unsigned binary number, most significant byte first
    Return int"""
    return int.from_bytes(bytes=p, byteorder="big", signed=False)


def int2bytes(x: int):
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
    # return x.to_bytes(length=bit_len // 8, byteorder="big", signed=False)