"""How should an ERC-8183 evaluator committee be designed so rater severities land on one scale?

Synthetic simulation only (no chain data): raters with known severities rate jobs with known quality under three
designs, and we measure whether the estimates recover the truth.
  fixed   : raters split into fixed committees; each job goes to one committee (no shared ratings across them)
  rotate  : each job draws a fresh random committee from all raters
  anchors : fixed committees, plus a few calibration jobs of known quality that every committee rates
Output: severity RMSE vs truth (same centering for truth and estimate), median SE, disconnected groups, and the
number of jobs needed for median SE <= target. Deterministic seeds.

usage: python simulate_design.py [out.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from mfrm import fit  # noqa: E402

R = 21
SEV_SD = 0.7
Q_MEAN, Q_SD = 0.5, 1.0
REPS = 20


def make(design, n_jobs, c, n_anchor, rng):
    sev = rng.normal(0, SEV_SD, R)
    groups = np.array_split(rng.permutation(R), R // c)
    q = rng.normal(Q_MEAN, Q_SD, n_jobs + n_anchor)
    job, rater = [], []
    for j in range(n_jobs):
        if design == "rotate":
            members = rng.choice(R, c, replace=False)
        else:
            members = groups[rng.integers(len(groups))]
        job += [j] * len(members)
        rater += list(members)
    anchors = {}
    if design == "anchors":
        for a in range(n_anchor):
            jid = n_jobs + a
            anchors[jid] = q[jid]
            for g in groups:
                job += [jid] * len(g)
                rater += list(g)
    job, rater = np.array(job), np.array(rater)
    x = (rng.random(job.size) < 1 / (1 + np.exp(-(q[job] - sev[rater])))).astype(float)
    return sev, n_jobs + (n_anchor if design == "anchors" else 0), job, rater, x, anchors


def one(design, n_jobs, c, n_anchor, seed):
    rng = np.random.default_rng(seed)
    sev, nj, job, rater, x, anchors = make(design, n_jobs, c, n_anchor, rng)
    f = fit(nj, R, job, rater, x, anchors=anchors)
    if f.anchored:
        err = f.severity - sev  # absolute scale fixed by anchors
    else:
        err = (f.severity - f.severity.mean()) - (sev - sev.mean())
    return {"rmse": float(np.sqrt(np.mean(err ** 2))), "median_se": float(np.median(f.severity_se)),
            "components": f.n_components, "ratings_per_rater": float(job.size / R)}


def main(out):
    rows = []
    for c in (3, 7):
        for design in ("fixed", "rotate", "anchors"):
            for n_jobs in (63, 126, 252, 504, 1008):
                res = [one(design, n_jobs, c, 6, 1000 * n_jobs + 17 * c + i) for i in range(REPS)]
                rows.append({"committee": c, "design": design, "jobs": n_jobs,
                             "ratings_per_rater": round(np.mean([r["ratings_per_rater"] for r in res]), 1),
                             "severity_rmse": round(float(np.mean([r["rmse"] for r in res])), 3),
                             "median_se": round(float(np.mean([r["median_se"] for r in res])), 3),
                             "groups": round(float(np.mean([r["components"] for r in res])), 1)})
                print(rows[-1], flush=True)
    need = {}
    for target in (0.3, 0.2):
        for c in (3, 7):
            for design in ("fixed", "rotate", "anchors"):
                ok = [r for r in rows if r["committee"] == c and r["design"] == design and r["median_se"] <= target]
                need[f"se<={target} c={c} {design}"] = min((r["jobs"] for r in ok), default=None)
    res = {"raters": R, "severity_sd": SEV_SD, "quality": [Q_MEAN, Q_SD], "reps": REPS, "anchor_jobs": 6,
           "synthetic": True, "rows": rows, "jobs_needed": need}
    Path(out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps(need, indent=1))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "simulate_design_result.json")
