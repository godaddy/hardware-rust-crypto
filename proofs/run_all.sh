#!/usr/bin/env bash
# Run the full machine-checked proof suite. Exits non-zero if any proof fails.
# Requires: python3 with z3-solver and sympy (pip install z3-solver sympy).
set -euo pipefail
cd "$(dirname "$0")"
echo "==> field_model.py   (model == real code == RFC 8452 POLYVAL)"
python3 field_model.py
echo "==> prove_multiply.py   (field multiply == POLYVAL dot, all inputs)"
python3 prove_multiply.py
echo "==> prove_aggregation.py   (reductions linear => reduce-once exact)"
python3 prove_aggregation.py
echo "==> prove_ghash_identity.py   (Horner == sum-of-powers)"
python3 prove_ghash_identity.py
echo "==> ALL PROOFS PASSED"
