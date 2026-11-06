"""Many-facet Rasch estimation for ERC-8183 evaluator panels (dichotomous: complete=1 / reject=0).

Model: P(x=1 | job j, rater r) = sigmoid(q_j - s_r), q = deliverable quality, s = rater severity (logits).
Estimation: joint maximum a posteriori (JMLE with weak normal priors, so jobs every rater passed or failed stay
finite; the quality prior is centred on the current mean quality, so shrinkage does not shift the scale),
alternating Newton steps. Standard errors from the model information of each parameter (the usual
Rasch-software approximation). Fit: infit / outfit mean squares per rater. With few raters per job, joint estimation deflates them (about
(L-1)/L), so fit_null() calibrates them against data simulated from the fitted model (parametric bootstrap).
Identification: if anchor jobs with known quality exist, they fix the scale; otherwise the mean severity of each
connected component is set to 0, and severities in different components are NOT comparable (reported).

Method credit: many-facet Rasch measurement (Linacre); its use for ERC-8183 evaluator panels was proposed by
@drmattbarney on the ERC-8183 thread (#441). This file is a plain reference implementation, not his software.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


@dataclass
class Fit:
    severity: np.ndarray
    severity_se: np.ndarray
    quality: np.ndarray
    quality_se: np.ndarray
    infit: np.ndarray
    outfit: np.ndarray
    component_of_rater: np.ndarray
    n_components: int
    anchored: bool
    iterations: int
    notes: list = field(default_factory=list)


def components(n_jobs: int, n_raters: int, job: np.ndarray, rater: np.ndarray) -> np.ndarray:
    """Connected components of the bipartite job-rater graph; returns component id per rater (-1 if unrated)."""
    parent = list(range(n_jobs + n_raters))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    for j, r in zip(job.tolist(), rater.tolist()):
        a, b = find(j), find(n_jobs + r)
        if a != b:
            parent[a] = b
    comp = np.full(n_raters, -1)
    seen = set(rater.tolist())
    roots = {}
    for r in range(n_raters):
        if r in seen:
            root = find(n_jobs + r)
            comp[r] = roots.setdefault(root, len(roots))
    return comp


def fit(n_jobs: int, n_raters: int, job: np.ndarray, rater: np.ndarray, x: np.ndarray,
        anchors: dict | None = None, prior_q_sd: float = 2.0, prior_s_sd: float = 3.0,
        max_iter: int = 200, tol: float = 1e-6) -> Fit:
    job, rater, x = np.asarray(job), np.asarray(rater), np.asarray(x, float)
    anchors = anchors or {}
    a_idx = np.array(sorted(anchors), dtype=int)
    a_val = np.array([anchors[k] for k in sorted(anchors)], float)
    free = np.ones(n_jobs, bool)
    free[a_idx] = False
    q = np.zeros(n_jobs)
    q[a_idx] = a_val
    s = np.zeros(n_raters)
    comp = components(n_jobs, n_raters, job, rater)
    ncomp = int(comp.max() + 1) if comp.size else 0
    anchored_comps = set(comp[np.unique(rater[np.isin(job, a_idx)])].tolist()) if a_idx.size else set()
    it = 0
    for it in range(1, max_iter + 1):
        p = sigmoid(q[job] - s[rater])
        w = p * (1 - p)
        # quality step (free jobs only)
        mu = q[free].mean() if free.any() else 0.0  # empirical-Bayes centre, so shrinkage does not move the scale
        gq = np.bincount(job, x - p, n_jobs) - (q - mu) / prior_q_sd ** 2
        hq = np.bincount(job, w, n_jobs) + 1 / prior_q_sd ** 2
        dq = np.where(free, gq / hq, 0.0)
        q += np.clip(dq, -1, 1)
        p = sigmoid(q[job] - s[rater])
        w = p * (1 - p)
        gs = -np.bincount(rater, x - p, n_raters) - s / prior_s_sd ** 2
        hs = np.bincount(rater, w, n_raters) + 1 / prior_s_sd ** 2
        ds = gs / hs
        s += np.clip(ds, -1, 1)
        # identification for components without anchors: mean severity 0, shift their jobs too
        for c in range(ncomp):
            if c in anchored_comps:
                continue
            rs = comp == c
            m = s[rs].mean()
            s[rs] -= m
            js = np.isin(np.arange(n_jobs), np.unique(job[np.isin(rater, np.flatnonzero(rs))])) & free
            q[js] -= m
        if max(np.abs(dq).max(initial=0), np.abs(ds).max(initial=0)) < tol:
            break
    p = sigmoid(q[job] - s[rater])
    w = p * (1 - p)
    s_se = 1 / np.sqrt(np.bincount(rater, w, n_raters) + 1 / prior_s_sd ** 2)
    q_se = 1 / np.sqrt(np.bincount(job, w, n_jobs) + 1 / prior_q_sd ** 2)
    n_r = np.bincount(rater, minlength=n_raters)
    outfit = np.bincount(rater, (x - p) ** 2 / np.maximum(w, 1e-12), n_raters) / np.maximum(n_r, 1)
    infit = np.bincount(rater, (x - p) ** 2, n_raters) / np.maximum(np.bincount(rater, w, n_raters), 1e-12)
    notes = []
    if ncomp > 1 and len(anchored_comps) < ncomp:
        notes.append(f"{ncomp} disconnected rater groups; severities across groups are not on one scale")
    return Fit(s, s_se, q, q_se, infit, outfit, comp, ncomp, bool(a_idx.size), it, notes)


def fit_null(n_jobs, n_raters, job, rater, x, anchors=None, B: int = 20, seed: int = 0, **kw):
    """Fit plus a design-specific null for infit: refit B data sets simulated from the fitted model.
    Returns (Fit, infit_ratio) where infit_ratio = observed infit / mean null infit (about 1 when the model holds)."""
    f = fit(n_jobs, n_raters, job, rater, x, anchors=anchors, **kw)
    rng = np.random.default_rng(seed)
    p = sigmoid(f.quality[np.asarray(job)] - f.severity[np.asarray(rater)])
    null = np.zeros(n_raters)
    for _ in range(B):
        xs = (rng.random(p.size) < p).astype(float)
        null += fit(n_jobs, n_raters, job, rater, xs, anchors=anchors, **kw).infit
    return f, f.infit / np.maximum(null / B, 1e-12)
