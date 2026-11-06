"""Calibration run: ratings file (sdk/scripts/collect_ratings.mjs) -> rater severity table, reproducible by anyone.

    python calibrate.py ratings.json --out run.json [--anchors anchors.json] [--bootstrap 20] [--seed 0]

Output (format erc8183-calibration-run/0.1):
  runId      sha256 over the canonical JSON of {estimator (mfrm.py sha256), options, input ratings}. Put it in a
             verdict's `calibrationRun`; anyone holding the published ratings file recomputes the same runId and,
             with the same estimator, the same table.
  raters     keyId, severity and its standard error (logits, and x1e4 integers for severityE4/severitySeE4),
             infit/outfit, infit ratio against a parametric-bootstrap null (about 1 when the model holds),
             number of ratings, connected component.
  design     number of connected rater groups. Severities in different groups are NOT on one scale (spec,
             Security Considerations); a run with more than one group says so and the verdict SHOULD NOT carry
             a severity from it unless anchors tie the groups.
anchors.json: {"<item>": quality_logit, ...} fixes the absolute scale with items of known quality.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mfrm  # noqa: E402

FORMAT_IN = "erc8183-ratings/0.1"
FORMAT_OUT = "erc8183-calibration-run/0.1"


def canonical(obj) -> bytes:
    """JSON with sorted keys and no spaces. Inputs here hold only strings, integers and lists, for which this equals
    RFC 8785; floats are kept out of the hashed input on purpose."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return "0x" + hashlib.sha256(b).hexdigest()


def run(ratings_doc: dict, anchors: dict | None = None, bootstrap: int = 20, seed: int = 0) -> dict:
    if ratings_doc.get("format") != FORMAT_IN:
        raise ValueError(f"expected format {FORMAT_IN}, got {ratings_doc.get('format')}")
    rows = [{"rater": r["rater"].lower(), "item": r["item"], "x": int(r["x"])} for r in ratings_doc["ratings"]]
    for r in rows:
        if r["x"] not in (0, 1):
            raise ValueError(f"rating must be 0 or 1: {r}")
    rows.sort(key=lambda r: (r["item"], r["rater"]))
    seen = set()
    for r in rows:
        k = (r["rater"], r["item"])
        if k in seen:
            raise ValueError(f"duplicate rating {k}: the ratings file must have one rating per rater and item")
        seen.add(k)
    raters = sorted({r["rater"] for r in rows})
    items = sorted({r["item"] for r in rows})
    ri = {k: i for i, k in enumerate(raters)}
    ii = {k: i for i, k in enumerate(items)}
    job = np.array([ii[r["item"]] for r in rows], dtype=int)
    rater = np.array([ri[r["rater"]] for r in rows], dtype=int)
    x = np.array([r["x"] for r in rows], dtype=float)
    anchors = anchors or {}
    unknown = [a for a in anchors if a not in ii]
    if unknown:
        raise ValueError(f"anchor items not in the ratings: {unknown[:3]}")
    anchor_idx = {ii[k]: float(v) for k, v in anchors.items()}

    estimator_sha = sha256_hex((HERE / "mfrm.py").read_bytes())
    options = {"bootstrap": int(bootstrap), "seed": int(seed),
               "anchors": {k: format(float(v), ".6f") for k, v in sorted(anchors.items())}}
    hashed_input = {"estimator": {"file": "mfrm.py", "sha256": estimator_sha}, "options": options, "ratings": rows}
    run_id = sha256_hex(canonical(hashed_input))

    f, ratio = mfrm.fit_null(len(items), len(raters), job, rater, x, anchors=anchor_idx or None, B=bootstrap, seed=seed)
    n_by = np.bincount(rater, minlength=len(raters))
    table = []
    for i, k in enumerate(raters):
        table.append({
            "keyId": k,
            "ratings": int(n_by[i]),
            "severity": round(float(f.severity[i]), 4),
            "severitySe": round(float(f.severity_se[i]), 4),
            "severityE4": int(round(float(f.severity[i]) * 1e4)),
            "severitySeE4": int(round(float(f.severity_se[i]) * 1e4)),
            "infit": round(float(f.infit[i]), 4),
            "infitRatio": round(float(ratio[i]), 4),
            "outfit": round(float(f.outfit[i]), 4),
            "group": int(f.component_of_rater[i]),
        })
    out = {
        "format": FORMAT_OUT,
        "runId": run_id,
        "estimator": hashed_input["estimator"],
        "options": options,
        "inputRatingsSha256": sha256_hex(canonical(rows)),
        "design": {
            "raters": len(raters), "items": len(items), "ratings": len(rows),
            "connectedGroups": int(f.n_components), "anchored": bool(f.anchored),
            "comparableAcrossAllRaters": bool(f.n_components == 1 or f.anchored),
        },
        "raters": table,
        "notes": list(f.notes),
    }
    if not out["design"]["comparableAcrossAllRaters"]:
        out["notes"].append(f"{f.n_components} disconnected rater groups: severities are comparable only within a group")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("ratings")
    ap.add_argument("--out")
    ap.add_argument("--anchors")
    ap.add_argument("--bootstrap", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    doc = json.loads(pathlib.Path(a.ratings).read_text(encoding="utf-8"))
    anchors = json.loads(pathlib.Path(a.anchors).read_text(encoding="utf-8")) if a.anchors else None
    out = run(doc, anchors=anchors, bootstrap=a.bootstrap, seed=a.seed)
    text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
    if a.out:
        pathlib.Path(a.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print(json.dumps({"runId": out["runId"], **out["design"]}), file=sys.stderr)


if __name__ == "__main__":
    main()
