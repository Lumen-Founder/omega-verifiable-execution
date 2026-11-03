"""Dependency-free Ethereum primitives: keccak-256, RLP, static ABI words, secp256k1 (RFC 6979, low-s).

Scope: LOCAL TEST KEYS. This pure-Python ECDSA is not constant-time; a production signer must sit behind the
same `Signer` interface (HSM/KMS/hardware wallet) — the adapter never needs the key bytes, only sign_hash().
Correctness is checked by recovering our own signatures and by anvil accepting the transactions.
"""
import hashlib
import hmac
from Crypto.Hash import keccak as _keccak

P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def keccak(data):
    return _keccak.new(digest_bits=256, data=data).digest()


# --- RLP ---------------------------------------------------------------------
def _int_bytes(i):
    if type(i) is not int or i < 0:
        raise ValueError('RLP_INT')
    return i.to_bytes((i.bit_length() + 7) // 8, 'big') if i else b''


def _len_prefix(n, short):
    if n < 56:
        return bytes([short + n])
    b = _int_bytes(n)
    return bytes([short + 55 + len(b)]) + b


def rlp(x):
    if isinstance(x, int):
        x = _int_bytes(x)
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        return x if len(x) == 1 and x[0] < 0x80 else _len_prefix(len(x), 0x80) + x
    if isinstance(x, list):
        body = b''.join(rlp(i) for i in x)
        return _len_prefix(len(body), 0xC0) + body
    raise TypeError('RLP_TYPE')


# --- ABI (static types only) --------------------------------------------------
def selector(sig):
    return keccak(sig.encode())[:4]


def word(v):
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, int):
        if not 0 <= v < 2 ** 256:
            raise ValueError('ABI_RANGE')
        return v.to_bytes(32, 'big')
    if isinstance(v, (bytes, bytearray)) and len(v) == 20:
        return bytes(12) + bytes(v)
    if isinstance(v, (bytes, bytearray)) and len(v) == 32:
        return bytes(v)
    raise TypeError('ABI_TYPE')


def call_data(sig, *args):
    return selector(sig) + b''.join(word(a) for a in args)


def words(data):
    return [data[i:i + 32] for i in range(0, len(data), 32)]


# --- secp256k1 -----------------------------------------------------------------
def _inv(a, m):
    return pow(a, -1, m)


def _jadd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jdouble(p)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    x3 = (r * r - h3 - 2 * u1 * h2) % P
    return x3, (r * (u1 * h2 - x3) - s1 * h3) % P, h * z1 * z2 % P


def _jdouble(p):
    if p is None or p[1] == 0:
        return None
    x, y, z = p
    s = 4 * x * y * y % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    return x3, (m * (s - x3) - 8 * pow(y, 4, P)) % P, 2 * y * z % P


def _mul(k, pt):
    acc, add = None, (pt[0], pt[1], 1)
    while k:
        if k & 1:
            acc = _jadd(acc, add)
        add, k = _jdouble(add), k >> 1
    if acc is None:
        return None
    zi = _inv(acc[2], P)
    return acc[0] * zi * zi % P, acc[1] * zi * zi * zi % P


def _rfc6979(d, h):
    x, hb = d.to_bytes(32, 'big'), (int.from_bytes(h, 'big') % N).to_bytes(32, 'big')
    v, k = b'\x01' * 32, b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        c = int.from_bytes(v, 'big')
        if 1 <= c < N:
            return c
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def pub_to_address(pub):
    return keccak(pub[0].to_bytes(32, 'big') + pub[1].to_bytes(32, 'big'))[-20:]


def recover(h, y_parity, r, s):
    """-> 20-byte address that produced (r, s, y_parity) over hash h."""
    if not (1 <= r < N and 1 <= s < N) or y_parity not in (0, 1):
        raise ValueError('BAD_SIGNATURE')
    x = r
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if y % 2 != y_parity:
        y = P - y
    if (y * y - x ** 3 - 7) % P:
        raise ValueError('BAD_SIGNATURE')
    z = int.from_bytes(h, 'big') % N
    ri = _inv(r, N)
    a, b = _mul(s * ri % N, (x, y)), _mul((-z * ri) % N, G)
    q = _jadd((a[0], a[1], 1) if a else None, (b[0], b[1], 1) if b else None)
    zi = _inv(q[2], P)
    return pub_to_address((q[0] * zi * zi % P, q[1] * zi * zi * zi % P))


class Signer:
    address = None  # 20 bytes

    def sign_hash(self, h):
        """-> (y_parity, r, s) with low s."""
        raise NotImplementedError


class LocalTestSigner(Signer):
    """In-memory secp256k1 key for local chains and tests. The key never leaves this object: no repr, no pickling."""

    def __init__(self, secret):
        d = int.from_bytes(secret, 'big') if isinstance(secret, (bytes, bytearray)) else None
        if d is None or len(secret) != 32 or not 1 <= d < N:
            raise ValueError('BAD_TEST_KEY')
        self.__d = d
        self.address = pub_to_address(_mul(d, G))

    def sign_hash(self, h):
        z = int.from_bytes(h, 'big') % N
        k = _rfc6979(self.__d, h)
        R = _mul(k, G)
        r = R[0] % N
        s = _inv(k, N) * (z + r * self.__d) % N
        yp = R[1] & 1
        if s > N // 2:
            s, yp = N - s, yp ^ 1
        return yp, r, s

    def __repr__(self):
        return f'LocalTestSigner(address=0x{self.address.hex()})'

    def __reduce__(self):
        raise TypeError('signer is not serializable')


def sign_1559(signer, chain_id, nonce, max_priority, max_fee, gas, to, value, data):
    """-> (raw signed tx bytes, tx hash hex). `to` is 20 bytes, or b'' for contract creation."""
    fields = [chain_id, nonce, max_priority, max_fee, gas, to, value, data, []]
    h = keccak(b'\x02' + rlp(fields))
    yp, r, s = signer.sign_hash(h)
    raw = b'\x02' + rlp(fields + [yp, r, s])
    return raw, '0x' + keccak(raw).hex()


def create_address(sender, nonce):
    return keccak(rlp([sender, nonce]))[-20:]


# --- EIP-712 (static fields only) ------------------------------------------------
DOMAIN_TYPE = b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
SETTLE_TYPE = b'Settle(bytes32 key,bytes32 src,bytes32 dst,uint256 amount,uint64 deadline,bytes32 omegaDigest)'


def domain_separator(name, version, chain_id, contract):
    return keccak(keccak(DOMAIN_TYPE) + keccak(name.encode()) + keccak(version.encode()) + word(chain_id) + word(contract))


def settle_digest(domain_sep, key, src, dst, amount, deadline, omega_digest):
    struct = keccak(keccak(SETTLE_TYPE) + b''.join(word(x) for x in (key, src, dst, amount, deadline, omega_digest)))
    return struct, keccak(b'\x19\x01' + domain_sep + struct)


def sign_typed(signer, digest):
    """-> (v in {27, 28}, r, s) for ecrecover-style verification."""
    yp, r, s = signer.sign_hash(digest)
    return 27 + yp, r, s
