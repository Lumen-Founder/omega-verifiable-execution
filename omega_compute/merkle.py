"""Binary Merkle commitment over a trace of state hashes (leaf/node domain separated)."""
import hashlib

EMPTY = '0' * 64


def _leaf(h):
    return hashlib.sha256(b'\x00' + bytes.fromhex(h)).digest()


def _node(a, b):
    return hashlib.sha256(b'\x01' + a + b).digest()


def _levels(leaves):
    size = 1
    while size < len(leaves):
        size *= 2
    level = [_leaf(h) for h in leaves] + [_leaf(EMPTY)] * (size - len(leaves))
    out = [level]
    while len(level) > 1:
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        out.append(level)
    return out


class Tree:
    def __init__(self, leaves):
        if not leaves:
            raise ValueError('EMPTY_TRACE')
        self.n = len(leaves)
        self.levels = _levels(leaves)
        self.root = self.levels[-1][0].hex()

    def proof(self, i):
        if not 0 <= i < self.n:
            raise IndexError(i)
        path = []
        for level in self.levels[:-1]:
            path.append(level[i ^ 1].hex())
            i //= 2
        return path


def verify(root, n, i, leaf, path):
    """True iff `leaf` is entry i of an n-leaf tree with this root."""
    if type(i) is not int or not 0 <= i < n or type(path) is not list:
        return False
    depth = (n - 1).bit_length() if n > 1 else 0
    if len(path) != depth:
        return False
    try:
        h = _leaf(leaf)
        for sib in path:
            s = bytes.fromhex(sib)
            if len(s) != 32:
                return False
            h = _node(h, s) if i % 2 == 0 else _node(s, h)
            i //= 2
    except (ValueError, TypeError):
        return False
    return h.hex() == root
