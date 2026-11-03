"""Per-agent authority. Default deny: anything not explicitly allowed is refused.

Policies are versioned; a change is a new version, never an in-place edit.
`evaluate` runs at acceptance (with usage); `still_allows` re-checks the parts
that can change between acceptance and execution (revocation, validity window,
allow-lists) so a revoked agent cannot spend an already accepted intent.
"""
import json
from dataclasses import dataclass, asdict, fields


@dataclass(frozen=True)
class Policy:
    agent_id: str
    version: int
    source_account: str
    actions: frozenset
    targets: frozenset
    assets: frozenset
    max_per_intent: int
    max_fee_per_intent: int
    window_seconds: int
    max_spend_per_window: int
    max_calls_per_window: int
    valid_from: int
    valid_until: int
    max_ttl: int = 3600
    revoked: bool = False

    def __post_init__(self):
        for f in ('actions', 'targets', 'assets'):
            object.__setattr__(self, f, frozenset(getattr(self, f)))
        for f in ('version', 'max_per_intent', 'max_fee_per_intent', 'window_seconds', 'max_spend_per_window',
                  'max_calls_per_window', 'valid_from', 'valid_until', 'max_ttl'):
            if type(getattr(self, f)) is not int or getattr(self, f) < 0:
                raise ValueError(f'POLICY_FIELD:{f}')
        if '*' in self.targets or '*' in self.actions or '*' in self.assets:
            raise ValueError('POLICY_WILDCARD')  # explicit allow-lists only
        if self.window_seconds == 0 or self.version == 0:
            raise ValueError('POLICY_FIELD:window_or_version')

    def to_json(self):
        d = asdict(self)
        for f in ('actions', 'targets', 'assets'):
            d[f] = sorted(d[f])
        return json.dumps(d, sort_keys=True, separators=(',', ':'))

    @classmethod
    def from_json(cls, text):
        d = json.loads(text)
        return cls(**{f.name: d[f.name] for f in fields(cls)})

    def revoke(self):
        return Policy(**(asdict(self) | {'version': self.version + 1, 'revoked': True}))


def _static(policy, env, now):
    if policy is None:
        return 'NO_POLICY'
    if policy.revoked:
        return 'REVOKED'
    if now < policy.valid_from:
        return 'POLICY_NOT_YET_VALID'
    if now >= policy.valid_until:
        return 'POLICY_EXPIRED'
    if env['action'] not in policy.actions:
        return 'ACTION_DENIED'
    if env['target'] not in policy.targets:
        return 'TARGET_DENIED'
    if env['params']['asset'] not in policy.assets:
        return 'ASSET_DENIED'
    if int(env['params']['amount']) > policy.max_per_intent:
        return 'AMOUNT_OVER_INTENT_LIMIT'
    return None


def evaluate(policy, env, usage, now):
    """None = allowed, else a denial code. usage: {'spend': int, 'calls': int} inside the window."""
    code = _static(policy, env, now)
    if code:
        return code
    if env['expires_at'] - env['created_at'] > policy.max_ttl:
        return 'TTL_TOO_LONG'
    if usage['calls'] + 1 > policy.max_calls_per_window:
        return 'RATE_LIMITED'
    if usage['spend'] + int(env['params']['amount']) > policy.max_spend_per_window:
        return 'WINDOW_SPEND_EXCEEDED'
    return None


def still_allows(policy, env, now):
    return _static(policy, env, now)
