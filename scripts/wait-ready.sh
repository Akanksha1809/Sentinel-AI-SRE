#!/usr/bin/env bash
# Wait until every stack component reports ready, from the host side.
set -euo pipefail
TIMEOUT="${TIMEOUT:-180}"

declare -a CHECKS=(
  "prometheus|http://127.0.0.1:9090/-/ready"
  "alertmanager|http://127.0.0.1:9093/-/ready"
  "loki|http://127.0.0.1:3100/ready"
  "alloy|http://127.0.0.1:12345/-/ready"
  "grafana|http://127.0.0.1:3000/api/health"
  "actuator|http://127.0.0.1:8085/readyz"
  "sentinel-api|http://127.0.0.1:8080/readyz"
)

deadline=$(( $(date +%s) + TIMEOUT ))
for check in "${CHECKS[@]}"; do
  name="${check%%|*}"; url="${check#*|}"
  printf '%-14s' "$name"
  until curl -fsS -m 3 -o /dev/null "$url" 2>/dev/null; do
    if (( $(date +%s) > deadline )); then
      echo "NOT READY after ${TIMEOUT}s ($url)"; exit 1
    fi
    sleep 2
  done
  echo "ready"
done

# Prometheus is discovering shop-api replicas through the actuator.
printf '%-14s' "shop-api"
until [[ "$(curl -fsS -m 3 'http://127.0.0.1:9090/api/v1/query?query=count(up%7Bjob%3D%22shop-api%22%7D%3D%3D1)' \
          | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else 0)')" -ge 1 ]]; do
  if (( $(date +%s) > deadline )); then echo "no shop-api targets up"; exit 1; fi
  sleep 2
done
echo "ready (scraped)"
