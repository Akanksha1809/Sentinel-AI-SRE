#!/usr/bin/env bash
# Generate local development secrets into ./secrets (gitignored).
# Never overwrites an existing secret, so it's safe to re-run.
# The directory is 0700 (other local users can't read it). Files are 0644 because
# Compose (non-swarm) bind-mounts them into containers that run as different UIDs.
set -euo pipefail
cd "$(dirname "$0")/.."

SECRETS=(
  postgres_password
  grafana_admin_password
  alertmanager_webhook_token
  actuator_token
  fault_token
  chaos_token
  deployer_token
  sentinel_migrator_db_password
  sentinel_app_db_password
  sentinel_admin_token
)

mkdir -p secrets
chmod 700 secrets
for name in "${SECRETS[@]}"; do
  f="secrets/${name}"
  if [[ -s "$f" ]]; then
    echo "exists:  $f"
  else
    openssl rand -hex 32 | tr -d '\n' > "$f"
    echo "created: $f"
  fi
  chmod 644 "$f"
done
