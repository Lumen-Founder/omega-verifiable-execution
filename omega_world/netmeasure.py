"""Read-only measurements on real public networks (docs/adr/ADR-0012 C5): no key, no transaction, no personal data;
only eth_feeHistory, eth_getBlockByNumber and eth_chainId on public RPC endpoints.

measure(url, blocks) -> base fee and priority fee percentiles over the last `blocks` blocks, block interval statistics
(the floor of inclusion latency: a transaction lands in the next block at the earliest) and gas fullness;
cost(m, gas) -> the fee in ETH (or the chain's native unit) for `gas` at those percentiles. On rollups this is the L2
execution fee only: the L1 data fee is NOT included (it depends on the rollup's own oracle and the calldata size).

    python -X utf8 -B -m omega_world.netmeasure <out.json> [gas_per_task]"""
import json
import statistics
import sys
import time
from omega_kernel.settlement.evm import Rpc

PUBLIC = {  # public endpoints without keys
    'ethereum-mainnet': 'https://ethereum-rpc.publicnode.com',
    'ethereum-sepolia': 'https://ethereum-sepolia-rpc.publicnode.com',
    'base-mainnet(L2 exec only)': 'https://base-rpc.publicnode.com',
    'optimism-mainnet(L2 exec only)': 'https://optimism-rpc.publicnode.com',
}


def _pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))]


def measure(url, blocks=1024, sample=120):
    rpc = Rpc(url, allow_remote=True, timeout=30)
    chain_id = int(rpc('eth_chainId'), 16)
    head = int(rpc('eth_blockNumber'), 16)
    base, prio, ratio = [], [], []
    left, newest = blocks, head
    while left > 0:  # many endpoints cap feeHistory at 1024 per call
        n = min(left, 1024)
        fh = rpc('eth_feeHistory', hex(n), hex(newest), [10, 50, 90])
        base += [int(x, 16) for x in fh['baseFeePerGas'][:-1]]
        prio += [[int(y, 16) for y in r] for r in fh.get('reward', [])]
        ratio += fh['gasUsedRatio']
        left -= n
        newest -= n
    stamps, gas_limit = [], None
    for b in range(head - sample, head + 1):
        block = rpc('eth_getBlockByNumber', hex(b), False)
        stamps.append(int(block['timestamp'], 16))
        gas_limit = int(block['gasLimit'], 16)
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    gwei = 1e9
    return {'chain_id': chain_id, 'head_block': head, 'blocks': len(base), 'measured_unix': int(time.time()),
            'block_gas_limit': gas_limit,
            'base_fee_gwei': {f'p{p}': _pct(base, p) / gwei for p in (10, 50, 90)} | {'max': max(base) / gwei},
            'priority_fee_gwei_median_of': {f'p{p}': statistics.median(r[i] for r in prio) / gwei
                                            for i, p in enumerate((10, 50, 90))} if prio else None,
            'gas_used_ratio_mean': round(statistics.mean(ratio), 4),
            'block_interval_s': {'mean': round(statistics.mean(gaps), 3), 'p50': _pct(gaps, 50), 'p90': _pct(gaps, 90),
                                 'max': max(gaps), 'sampled_blocks': len(gaps)}}


def cost(m, gas):
    tip = (m['priority_fee_gwei_median_of'] or {}).get('p50', 0)
    return {k: round(gas * (v + tip) * 1e-9, 8) for k, v in m['base_fee_gwei'].items()}


def run(gas_per_task, out=None):
    res = {'gas_per_task': gas_per_task, 'note': 'fee = gas x (base fee percentile + median p50 tip); rollups: L2 '
           'execution fee only, L1 data fee not included', 'networks': {}}
    for name, url in PUBLIC.items():
        try:
            m = measure(url)
            res['networks'][name] = m | {'cost_per_task_native': cost(m, gas_per_task)}
        except Exception as e:  # one unreachable endpoint must not hide the others
            res['networks'][name] = {'error': type(e).__name__ + ':' + str(e)[:200]}
    if out:
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=1)
    return res


if __name__ == '__main__':
    r = run(int(sys.argv[2]) if len(sys.argv) > 2 else 1_076_374, sys.argv[1])
    print(json.dumps({k: {x: v.get(x) for x in ('base_fee_gwei', 'block_interval_s', 'cost_per_task_native')}
                      for k, v in r['networks'].items()}, indent=1))
