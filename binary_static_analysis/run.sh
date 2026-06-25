#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT}"

./scripts/setup_tools.sh
python3 -m pip install -r requirements.txt
python3 agent.py --target challenge

