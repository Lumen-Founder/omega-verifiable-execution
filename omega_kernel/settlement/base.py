"""Chain-independent settlement contract the kernel depends on.

A transfer is a plain dict: source, target, asset, amount (int), fee_limit (int),
deadline (unix seconds). `submit` MUST be idempotent per key: the same key with
the same transfer returns the original outcome; the same key with a different
transfer is refused (KEY_REUSE). `status(key)` returns one of UNKNOWN (never
seen), PENDING, CONFIRMED, FAILED. If `deadline_enforced` is True, the backend
guarantees nothing with that key can settle after `deadline` — only then may the
kernel treat UNKNOWN-after-deadline as final (ADR-0001 R4).
"""
import hashlib
from omega_kernel.canonical import canonical

STATUSES = {'UNKNOWN', 'PENDING', 'CONFIRMED', 'FAILED'}


def transfer_digest(transfer):
    return hashlib.sha256(b'OMEGA-TRANSFER-v1\x00' + canonical({k: str(v) for k, v in transfer.items()})).hexdigest()


class SettlementAdapter:
    chain_id = 'abstract'
    deadline_enforced = False

    def estimate_fee(self, transfer):
        raise NotImplementedError

    def balance(self, account, asset):
        raise NotImplementedError

    def simulate(self, transfer):
        """-> {'ok': bool, 'code': str|None}. Must not change state."""
        raise NotImplementedError

    def submit(self, key, transfer, now):
        """-> {'status': PENDING|CONFIRMED|FAILED, 'ref': str|None, 'code': str|None, 'transfer_digest': str}.
        May raise on transport failure; the outcome is then unknown to the caller."""
        raise NotImplementedError

    def status(self, key):
        """-> {'status': one of STATUSES, 'ref', 'code', 'transfer_digest'}"""
        raise NotImplementedError
