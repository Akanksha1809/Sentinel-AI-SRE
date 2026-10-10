#!/usr/bin/env bash
# Record a sentinel-demo run as an asciinema .cast file.
# Usage: ./scripts/record-demo.sh <a|b|c> [output.cast]
set -euo pipefail
cd "$(dirname "$0")/.."

SCENARIO="${1:?usage: record-demo.sh <a|b|c> [output.cast]}"
OUT="${2:-demo-${SCENARIO}-$(date +%Y%m%d-%H%M%S).cast}"

if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema not found. Install it first:" >&2
  echo "  macOS:  brew install asciinema" >&2
  echo "  Linux:  pipx install asciinema  (or your package manager)" >&2
  exit 1
fi

if ! curl -fsS -m 3 -o /dev/null http://127.0.0.1:8080/readyz; then
  echo "sentinel-api is not ready at http://127.0.0.1:8080 — run 'make e2e-up' first" >&2
  echo "(SENTINEL_EXECUTION_MODE=live, so the recording shows a real fix, not a dry-run no-op)" >&2
  exit 1
fi

echo "Recording scenario ${SCENARIO} to ${OUT}..."
asciinema rec --overwrite -c "uv run sentinel-demo run ${SCENARIO}" "${OUT}"
echo "Done: ${OUT}"
echo "Play back:  asciinema play ${OUT}"
echo "Upload:     asciinema upload ${OUT}"
echo "To GIF:     agg ${OUT} ${OUT%.cast}.gif   (brew install agg / cargo install --locked agg)"
