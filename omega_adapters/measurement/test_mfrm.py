"""Checks for mfrm.py: recovery on a connected design, disconnection detection, anchor scale, fit sanity."""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from mfrm import components, fit, fit_null  # noqa: E402


def _sim(rng, n_jobs, n_raters, per_job, sev, q):
    job, rater = [], []
    for j in range(n_jobs):
        m = rng.choice(n_raters, per_job, replace=False)
        job += [j] * per_job
        rater += list(m)
    job, rater = np.array(job), np.array(rater)
    x = (rng.random(job.size) < 1 / (1 + np.exp(-(q[job] - sev[rater])))).astype(float)
    return job, rater, x


def test_recovers_severity_on_connected_design():
    rng = np.random.default_rng(1)
    sev = np.linspace(-1.2, 1.2, 9)
    q = rng.normal(0.3, 1.0, 1500)
    job, rater, x = _sim(rng, 1500, 9, 5, sev, q)
    f = fit(1500, 9, job, rater, x)
    est = f.severity - f.severity.mean()
    tru = sev - sev.mean()
    assert f.n_components == 1
    assert np.corrcoef(est, tru)[0, 1] > 0.98
    assert np.sqrt(np.mean((est - tru) ** 2)) < 0.15
    assert np.all(np.abs((est - tru) / f.severity_se) < 4)


def test_detects_disconnected_committees():
    job = np.array([0, 0, 1, 1, 2, 2, 3, 3])
    rater = np.array([0, 1, 0, 1, 2, 3, 2, 3])
    comp = components(4, 4, job, rater)
    assert comp[0] == comp[1] and comp[2] == comp[3] and comp[0] != comp[2]
    f = fit(4, 4, job, rater, np.array([1, 0, 1, 1, 0, 0, 1, 0.]))
    assert f.n_components == 2 and f.notes


def test_anchors_fix_absolute_scale():
    rng = np.random.default_rng(2)
    sev = np.array([-0.8, 0.0, 0.9, 1.5])
    q = rng.normal(0.5, 1.0, 1200)
    job, rater, x = _sim(rng, 1200, 4, 4, sev, q)
    anchors = {j: q[j] for j in range(40)}
    f = fit(1200, 4, job, rater, x, anchors=anchors)
    assert f.anchored
    assert np.max(np.abs(f.severity - sev)) < 0.25  # no centering: the anchors set the origin


def test_fit_near_one_when_model_holds():
    rng = np.random.default_rng(3)
    sev = rng.normal(0, 0.7, 12)
    q = rng.normal(0.5, 1.0, 2000)
    job, rater, x = _sim(rng, 2000, 12, 4, sev, q)
    _, ratio = fit_null(2000, 12, job, rater, x, B=10, seed=1)
    assert np.all((ratio > 0.9) & (ratio < 1.1)), ratio
    x2 = x.copy()
    m = rater == 0
    x2[m] = (rng.random(m.sum()) < 0.5).astype(float)  # rater 0 answers at random
    _, ratio2 = fit_null(2000, 12, job, rater, x2, B=10, seed=1)
    assert ratio2[0] > 1.1 and ratio2[0] > np.max(ratio2[1:]), ratio2


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
