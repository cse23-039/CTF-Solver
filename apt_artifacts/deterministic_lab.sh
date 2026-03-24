#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./snapshots ./replays ./net
echo "[LAB] profile=docker target=challenge"

# deterministic seed & env
export PYTHONHASHSEED=0
export TZ=UTC
export LANG=C.UTF-8

# snapshot/revert stubs
echo "[LAB] snapshot create" > ./snapshots/latest.snapshot
echo "[LAB] revert to snapshot ./snapshots/latest.snapshot"

# network shaping (best-effort)
if command -v tc >/dev/null 2>&1; then
  sudo tc qdisc add dev lo root netem delay 80ms loss 0.5% rate 10mbit 2>/dev/null || true
fi

# reproducible replay entrypoint
cat > ./replays/replay.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[REPLAY] running deterministic exploit replay"
EOF
chmod +x ./replays/replay.sh
echo "[LAB] ready"
