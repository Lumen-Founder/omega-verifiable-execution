"""Intent envelope: strict schema, canonical digest, agent authentication.

Amounts are integer strings in minor units (no floats anywhere). Identifiers are
ASCII-only so look-alike Unicode cannot alias an agent or account. Field names
that look like secrets are refused: an envelope is journaled, so it must never
carry credentials.
"""
import hashlib
import hmac
import json
import re
from omega_kernel.canonical import canonical

VERSION = 1
MAX_BYTES = 4096
DOMAIN = b'OMEGA-INTENT-v1\x00'
HEX32 = re.compile(r'[0-9a-f]{32}')
AGENT = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}')
ACCOUNT = re.compile(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}')
ASSET = re.compile(r'[A-Z0-9]{1,16}')
AMOUNT = re.compile(r'[1-9][0-9]{0,29}')
FEE = re.compile(r'0|[1-9][0-9]{0,29}')
SENSITIVE = re.compile(r'secret|private|passw|token|mnemonic|seed|api.?key|auth|credential', re.I)
TOP = {'v', 'intent_id', 'agent_id', 'nonce', 'action', 'target', 'params', 'constraints', 'created_at', 'expires_at'}
OPTIONAL = {'constraints'}
# action -> (required params, allowed constraints)
ACTIONS = {'transfer': ({'asset', 'amount'}, {'max_fee'})}
MAX_TIME = 2 ** 40
MAX_NONCE = 2 ** 63 - 1


class EnvelopeError(ValueError):
    def __init__(self, code, detail=''):
        super().__init__(f'{code}:{detail}' if detail else code)
        self.code = code


def _no_float(_):
    raise EnvelopeError('INVALID_NUMBER')


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise EnvelopeError('DUPLICATE_KEY', k)
        out[k] = v
    return out


def decode(raw):
    """bytes/str JSON -> dict. Rejects duplicate keys, floats, NaN/Infinity, oversize."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_BYTES:
            raise EnvelopeError('TOO_LARGE')
        try:
            raw = bytes(raw).decode('utf-8')
        except UnicodeDecodeError:
            raise EnvelopeError('INVALID_UTF8') from None
    if not isinstance(raw, str):
        raise EnvelopeError('NOT_JSON_TEXT')
    if len(raw.encode('utf-8')) > MAX_BYTES:
        raise EnvelopeError('TOO_LARGE')
    try:
        return json.loads(raw, parse_float=_no_float, parse_constant=_no_float, object_pairs_hook=_pairs)
    except EnvelopeError:
        raise
    except ValueError:
        raise EnvelopeError('INVALID_JSON') from None


def _int(v, lo, hi, code):
    if type(v) is not int or not lo <= v <= hi:
        raise EnvelopeError(code)
    return v


def _str(v, pattern, code):
    if type(v) is not str or not pattern.fullmatch(v):
        raise EnvelopeError(code)
    return v


def _flat(v, allowed, required, code):
    if type(v) is not dict:
        raise EnvelopeError(code)
    for k in v:
        if type(k) is not str or SENSITIVE.search(k):
            raise EnvelopeError('SENSITIVE_FIELD', str(k))
    extra = set(v) - allowed
    if extra:
        raise EnvelopeError('UNKNOWN_FIELD', sorted(extra)[0])
    if required - set(v):
        raise EnvelopeError('MISSING_FIELD', sorted(required - set(v))[0])
    return v


def parse(raw):
    """raw JSON text/bytes or an already-decoded dict -> normalized envelope dict."""
    d = raw if type(raw) is dict else decode(raw)
    if type(d) is not dict:
        raise EnvelopeError('NOT_OBJECT')
    for k in d:
        if type(k) is str and SENSITIVE.search(k):
            raise EnvelopeError('SENSITIVE_FIELD', k)
    if set(d) - TOP:
        raise EnvelopeError('UNKNOWN_FIELD', sorted(set(d) - TOP)[0])
    if TOP - OPTIONAL - set(d):
        raise EnvelopeError('MISSING_FIELD', sorted(TOP - OPTIONAL - set(d))[0])
    _int(d['v'], VERSION, VERSION, 'BAD_VERSION')
    _str(d['intent_id'], HEX32, 'BAD_INTENT_ID')
    _str(d['agent_id'], AGENT, 'BAD_AGENT_ID')
    _int(d['nonce'], 1, MAX_NONCE, 'BAD_NONCE')
    if type(d['action']) is not str or d['action'] not in ACTIONS:
        raise EnvelopeError('UNKNOWN_ACTION')
    _str(d['target'], ACCOUNT, 'BAD_TARGET')
    _int(d['created_at'], 0, MAX_TIME, 'BAD_TIME')
    _int(d['expires_at'], 0, MAX_TIME, 'BAD_TIME')
    if d['expires_at'] <= d['created_at']:
        raise EnvelopeError('BAD_EXPIRY')
    required, allowed_constraints = ACTIONS[d['action']]
    p = _flat(d['params'], required, required, 'BAD_PARAMS')
    _str(p['asset'], ASSET, 'BAD_ASSET')
    _str(p['amount'], AMOUNT, 'BAD_AMOUNT')
    c = _flat(d.get('constraints', {}), allowed_constraints, set(), 'BAD_CONSTRAINTS')
    if 'max_fee' in c:
        _str(c['max_fee'], FEE, 'BAD_MAX_FEE')
    env = {k: d[k] for k in TOP - OPTIONAL} | {'params': dict(p), 'constraints': dict(c)}
    if len(canonical(env)) > MAX_BYTES:
        raise EnvelopeError('TOO_LARGE')
    return env


def digest(env):
    return hashlib.sha256(DOMAIN + canonical(env)).hexdigest()


def tag(key, env):
    """Authentication tag an agent attaches. HMAC-SHA256 placeholder for signatures (ADR-0001 R1)."""
    return hmac.new(key, DOMAIN + canonical(env), hashlib.sha256).hexdigest()


def verify_tag(key, env, value):
    return type(value) is str and hmac.compare_digest(tag(key, env), value)


class KeyRing:
    """agent_id -> key bytes. Never serialized; repr shows only the count."""

    def __init__(self, keys=None):
        self._keys = {}
        for a, k in (keys or {}).items():
            self.add(a, k)

    def add(self, agent_id, key):
        _str(agent_id, AGENT, 'BAD_AGENT_ID')
        if type(key) is not bytes or len(key) < 32:
            raise ValueError('KEY_TOO_SHORT')
        self._keys[agent_id] = key

    def get(self, agent_id):
        return self._keys.get(agent_id)

    def __repr__(self):
        return f'KeyRing(<{len(self._keys)} keys>)'

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError('KeyRing is not serializable')
