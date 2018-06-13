import hmac
import collections
import ecdsa
from bytes import bytes2int, int2bytes

# curve implementation from https://github.com/andreacorbellini/ecc

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')
curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)

# end curve implementation


def get_point_coord(private_key: int) -> tuple:
    """Get public key as a coordinate point on secp256k1 curve, corresponding to given private key"""
    sk = ecdsa.SigningKey.from_secret_exponent(private_key, ecdsa.SECP256k1)
    public_key = sk.get_verifying_key().pubkey.point
    return public_key


def ser_compress_coord_point(point):
    """
    Serialize the coordinate pair *point* = (x,y) as a byte sequence using SEC1's compressed form:
    (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
    """
    y_byte = bytes.fromhex("03") if (point[1] & 1) else bytes.fromhex("02")
    return y_byte + int2bytes(point[0])


def ser_coord_point(point: tuple, include_prefix: bool) -> bytes:
    """
    Serialize the coordinate pair *point* = (x,y) as a byte sequence using SEC1's uncompressed form:
    0x04 || ser256(x) || ser256(y).
    """
    serialized = int2bytes(point[0]) + int2bytes(point[1])
    return bytes.fromhex("04") + serialized if include_prefix else serialized


def serialize_key(version: str, key, chain_code: bytes, key_type: str, depth: str = "00"):
    """
    Serialize extended HD key
    """
    # TODO: remove dummy values with values, implement full key serialization algorithm
    depth = bytes.fromhex(depth)
    fingerprint = bytes.fromhex("00000000")
    child_num = bytes.fromhex("00000000")
    if key_type == "public":
        if version == "mainnet":
            version_bytes = bytes.fromhex("0488B21E")
        key = ser_compress_coord_point(key)
    else:
        if version == "testnet":
            version_bytes = bytes.fromhex("0488ADE4")
        key = bytes.fromhex("00") + int2bytes(key)
    return version_bytes + depth + fingerprint + child_num + chain_code + key


def master_key(seed: bytes) -> (int, bytes):
    """
    Take seed byte sequence between 128 and 512 bits
    Generate a BIP32 master private key and a master chain code for HD cryptocurrency wallet
    Return master private key as integer, master chain code as 32-byte sequence
    """
    assert (128 / 8 <= len(seed) <= 512 / 8)
    I = hmac.new(key=b"Bitcoin seed", msg=seed, digestmod="SHA512")
    il, ir = I.digest()[:32], I.digest()[32:]
    master_pk = bytes2int(il)
    master_cc = ir
    assert master_pk < ecdsa.SECP256k1.curve.n - 1
    return master_pk, master_cc


def private_to_private(pk: int, cc, i):
    """
    Child key derivation
    """
    if i >= 2 ** 31:
        # child key is hardened
        I = hmac.new(cc, b'\x00' + pk.to_bytes(32, byteorder="big", signed=False)
                     + i.to_bytes(4, byteorder="big", signed=False), 'SHA512')
    else:
        # child key is not hardened
        I = hmac.new(cc, ser_compress_coord_point(get_point_coord(pk)) + int2bytes(i), 'SHA512')
    il = I.digest()[:32]
    ir = I.digest()[32:]  # chain code

    ki = (bytes2int(il) + pk) % curve.n
    assert (ki != 0)
    assert (int.from_bytes(il, byteorder="big", signed=False) < curve.n)

    return ki, ir


def public_to_public(point: tuple, cc, i):
    """
    Child key derivation
    """
    if i >= 2 ** 31:
        # child key is hardened
        return False
    else:
        # child key is not hardened
        I = hmac.new(cc, ser_compress_coord_point(point) + int2bytes(i), 'SHA512')
    il = I.digest()[:32]
    ir = I.digest()[32:]  # chain code

    il_int = bytes2int(il)
    assert (il_int < curve.n)

    Ki = get_point_coord(il_int) + point

    return Ki, ir


def private_to_public(pk, cc):
    public = get_point_coord(pk)
    return public, cc