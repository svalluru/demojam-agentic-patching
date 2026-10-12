#!/usr/bin/env python3
"""Build a training set from the synthetic baseline plus observed outcomes.

    ./build_dataset.py                      # writes data.csv, drops simulated
    ./build_dataset.py --include-simulated  # for testing the pipeline only
    ./build_dataset.py --observed-only      # no synthetic rows

Why this exists: agent 4 appends one row per settled host to
observed/outcomes.csv, which carries provenance columns the model does not
take. Something has to reduce that to the five columns save_model.py expects
and decide what to let through. Doing it here rather than in the agent keeps
the agent append-only — it never has to rewrite or filter what it wrote.

Simulated rows are excluded by default. In offline mode every run is
simulated, so a few demo runs would otherwise silently become ground truth.

Note save_model.py reads data.csv from this directory, which is not in the
repo — it has to be generated. That is what this script is for.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEATURES = ['cvss', 'age_days', 'affected_hosts', 'type', 'risk_score']
SYNTHETIC = HERE / 'xgboost_local' / 'data.csv'
OBSERVED = HERE / 'observed' / 'outcomes.csv'
OUT = HERE / 'data.csv'


def read_synthetic(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline='') as fh:
        return [{k: r[k] for k in FEATURES} for r in csv.DictReader(fh)]


def read_observed(path: Path, include_simulated: bool) -> tuple[list[dict], int]:
    if not path.exists():
        return [], 0
    rows, dropped = [], 0
    with path.open(newline='') as fh:
        for r in csv.DictReader(fh):
            if str(r.get('simulated', '')).strip().lower() in ('true', '1', 'yes'):
                if not include_simulated:
                    dropped += 1
                    continue
            if any(r.get(k) in (None, '') for k in FEATURES):
                dropped += 1          # an incomplete row would train on blanks
                continue
            rows.append({k: r[k] for k in FEATURES})
    return rows, dropped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--include-simulated', action='store_true',
                    help='keep rows from simulated runs (pipeline testing only)')
    ap.add_argument('--observed-only', action='store_true',
                    help='exclude the synthetic baseline')
    ap.add_argument('--out', default=str(OUT))
    args = ap.parse_args()

    synth = [] if args.observed_only else read_synthetic(SYNTHETIC)
    obs, dropped = read_observed(OBSERVED, args.include_simulated)

    if not synth and not obs:
        print(f'nothing to build: no rows in {SYNTHETIC} or {OBSERVED}',
              file=sys.stderr)
        return 1

    out = Path(args.out)
    with out.open('w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=FEATURES)
        w.writeheader()
        w.writerows(synth + obs)

    print(f'  synthetic : {len(synth)} rows')
    print(f'  observed  : {len(obs)} rows'
          + (f'  ({dropped} dropped — simulated or incomplete)' if dropped else ''))
    print(f'  wrote     : {out}  ({len(synth) + len(obs)} rows)')
    if obs:
        print('\n  Retrain with:  cd risk_score/training && python save_model.py')
    else:
        print('\n  No observed outcomes yet — this is the synthetic baseline only.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
