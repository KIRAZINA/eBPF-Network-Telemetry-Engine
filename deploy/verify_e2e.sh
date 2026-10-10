#!/usr/bin/env bash
# verify_e2e.sh — end-to-end observability verification for the compose stack.
#
# Flow: stack health -> Prometheus targets UP -> synthetic SYN-flood + port
# scan (contrib/synth_traffic.py, needs root) -> metric spike in Prometheus
# -> alert(s) FIRING -> Grafana dashboard provisioned.
#
# Usage (Linux / WSL2 docker host, repo root):
#   IFINDEX=2 GRAFANA_ADMIN_PASSWORD=admin ./deploy/verify_e2e.sh
# Env knobs: PROM_URL (default http://localhost:9091), GRAFANA_URL
# (default http://localhost:3000), TARGET (default 127.0.0.1).
set -u
PROM_URL="${PROM_URL:-http://localhost:9091}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
TARGET="${TARGET:-127.0.0.1}"
PASS=0; FAIL=0

ok()   { PASS=$((PASS + 1)); echo "[+] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[-] $1"; }

echo "=== [1/5] stack health ==="
docker compose ps --format '{{.Name}} {{.Health}} {{.State}}'
curl -sf "$PROM_URL/-/healthy" >/dev/null \
    && ok "Prometheus healthy" \
    || fail "Prometheus not healthy at $PROM_URL"
curl -sf "$GRAFANA_URL/api/health" >/dev/null \
    && ok "Grafana healthy" \
    || fail "Grafana not healthy at $GRAFANA_URL"

echo "=== [2/5] Prometheus targets UP ==="
if curl -sf "$PROM_URL/api/v1/targets?state=active" | grep -q '"health":"up"'; then
    ok "at least one target up"
else
    fail "no target up (daemon scraped via host.docker.internal:9090?)"
fi
curl -sf "$PROM_URL/api/v1/query?query=up%7Bjob%3D%22ebpf-telemetry%22%7D" | grep -q '"value":\[[0-9]*,"1"\]' \
    && ok 'up{job="ebpf-telemetry"} == 1' \
    || fail 'up{job="ebpf-telemetry"} != 1'

echo "=== [3/5] synthetic traffic (needs root for raw sockets) ==="
sudo python3 contrib/synth_traffic.py --target "$TARGET" \
    --syn-count 400 --ports 80,443,8000-8020 \
    && ok "synthetic SYN burst + port scan sent" \
    || fail "synth_traffic.py failed"

echo "=== [4/5] metric spike + firing alerts (allows 90s for for-windows) ==="
sleep 20
Q_SPike='sum(rate(telemetry_anomalies_detected_total%7Btype%3D%22syn_flood%22%7D%5B1m%5D))'
if curl -sf "$PROM_URL/api/v1/query?query=$Q_SPike" | grep -Eq '"value":\[[0-9]+,"(0\.[0-9]*[1-9]|[1-9][0-9]*)'; then
    ok "syn_flood verdict rate > 0 in Prometheus"
else
    fail "no syn_flood rate observed (XDP may be unavailable on this NIC)"
fi
for _ in $(seq 1 9); do
    ALERTS=$(curl -sf "$PROM_URL/api/v1/alerts" 2>/dev/null || echo '')
    if echo "$ALERTS" | grep -q '"name":"SynFloodSpike","state":"firing"'; then
        ok "SynFloodSpike FIRING"; break
    fi
    if [ "$_" = 9 ]; then
        fail "SynFloodSpike not firing after ~90s (check thresholds/traffic)"
    fi
    sleep 10
done
curl -sf "$PROM_URL/api/v1/alerts" | grep -q '"name":"DaemonDown"' \
    && ok "DaemonDown rule loaded (inactive while daemon is up)" \
    || fail "DaemonDown rule missing"

echo "=== [5/5] Grafana dashboard provisioned =="
curl -sf -u "admin:${GRAFANA_ADMIN_PASSWORD:-admin}" \
    "$GRAFANA_URL/api/dashboards/uid/ebpf-telemetry" | grep -q '"title":"eBPF Network Telemetry"' \
    && ok "dashboard ebpf-telemetry importable via API" \
    || fail "dashboard missing (check provisioning mounts)"

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
