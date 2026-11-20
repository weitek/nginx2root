#!/usr/bin/env bash
# Integration test: real nginx in Docker, four configurations.
#
#   tests/integration/run.sh
#
# Requires docker and openssl. Exit code 0 means every expected verdict was
# produced; 77 means the environment cannot run the test (missing tools etc.).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/nginx2root-int.XXXXXX")"
PREFIX="n2r-int-$$"
CONTAINERS=()

cleanup() {
  for name in "${CONTAINERS[@]:-}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

skip() { echo "SKIP: $*"; exit 77; }

command -v docker >/dev/null || skip "docker не найден"
command -v openssl >/dev/null || skip "openssl не найден"
docker info >/dev/null 2>&1 || skip "docker daemon недоступен"

echo "==> сертификат"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
  -subj "/CN=localhost" >/dev/null 2>&1
chmod 644 "$TMP/cert.pem" "$TMP/key.pem"

free_port() {
  python3 - <<'PY'
import socket
for _ in range(50):
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.bind(("127.0.0.1", port))
    except OSError:
        tcp.close(); udp.close(); continue
    tcp.close(); udp.close()
    print(port)
    break
else:
    raise SystemExit("no free port")
PY
}

write_conf() {
  local name="$1" mode="$2"
  local listen_lines ssl_lines
  case "$mode" in
    h2)
      listen_lines=$'    listen 8443 ssl;\n    http2 on;'
      ssl_lines=""
      ;;
    h1)
      listen_lines=$'    listen 8443 ssl;\n    http2 off;'
      ssl_lines=""
      ;;
    h3)
      listen_lines=$'    listen 8443 ssl;\n    listen 8443 quic reuseport;\n    http3 on;'
      ssl_lines=$'    add_header Alt-Svc \'h3=":8443"; ma=3600\' always;'
      ;;
    *)
      echo "unknown mode $mode" >&2; exit 1
      ;;
  esac
  cat > "$TMP/$name.conf" <<EOF
worker_processes 1;
events { worker_connections 64; }
http {
    server_tokens on;
    access_log off;
    server {
$listen_lines
        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;
$ssl_lines
        location / { return 200 "ok\\n"; }
    }
}
EOF
}

start_nginx() {
  local name="$1" image="$2" conf="$3" port="$4" udp="${5:-no}"
  local args=(
    -d --name "$name" --rm
    --entrypoint nginx
    -v "$TMP/$conf.conf:/etc/nginx/nginx.conf:ro"
    -v "$TMP/cert.pem:/etc/nginx/certs/cert.pem:ro"
    -v "$TMP/key.pem:/etc/nginx/certs/key.pem:ro"
    -p "127.0.0.1:$port:8443"
  )
  if [ "$udp" = "yes" ]; then
    args+=(-p "127.0.0.1:$port:8443/udp")
  fi
  CONTAINERS+=("$name")
  docker run "${args[@]}" "$image" -g "daemon off;" >/dev/null
}

wait_port() {
  local port="$1"
  python3 - "$port" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 20
while time.time() < deadline:
    try:
        sock = socket.create_connection(("127.0.0.1", port), 1)
        sock.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit(1)
PY
}

echo "==> запуск контейнеров"
write_conf h2-vuln h2
write_conf h1-vuln h1
write_conf h2-patched h2
write_conf h3-vuln h3

P_H2_VULN="$(free_port)"
P_H1_VULN="$(free_port)"
P_H2_PATCHED="$(free_port)"
P_H3_VULN="$(free_port)"

start_nginx "${PREFIX}-h2-vuln"     nginx:1.31.8-alpine h2-vuln   "$P_H2_VULN"
start_nginx "${PREFIX}-h1-vuln"     nginx:1.31.8-alpine h1-vuln   "$P_H1_VULN"
start_nginx "${PREFIX}-h2-patched"  nginx:1.31-alpine   h2-patched "$P_H2_PATCHED"
start_nginx "${PREFIX}-h3-vuln"     nginx:1.31.8-alpine h3-vuln   "$P_H3_VULN" yes

for port in "$P_H2_VULN" "$P_H1_VULN" "$P_H2_PATCHED" "$P_H3_VULN"; do
  wait_port "$port" || { echo "nginx не поднялся на порту $port" >&2; exit 1; }
done

echo "==> проверки"
check() {
  local label="$1" port="$2" out="$3"
  python3 "$ROOT/nginx2root_check.py" "https://127.0.0.1:$port" \
    --timeout 5 --json > "$out" || true
}

check h2-vuln    "$P_H2_VULN"    "$TMP/h2-vuln.json"
check h1-vuln    "$P_H1_VULN"    "$TMP/h1-vuln.json"
check h2-patched "$P_H2_PATCHED" "$TMP/h2-patched.json"
check h3-vuln    "$P_H3_VULN"    "$TMP/h3-vuln.json"

python3 - "$TMP" <<'PY'
import json
import os
import sys

tmp = sys.argv[1]
cases = [
    ("h2-vuln",     "CVE-2026-123007", "LIKELY_VULNERABLE", 1),
    ("h1-vuln",     "CVE-2026-123007", "MITIGATED",         2),
    ("h2-patched",  "CVE-2026-123007", "PATCHED",           0),
    ("h3-vuln",     "CVE-2026-121810", "LIKELY_VULNERABLE", 1),
]
failed = False
for name, cve, expected, expected_exit in cases:
    with open(os.path.join(tmp, name + ".json"), encoding="utf-8") as handle:
        data = json.load(handle)
    result = data["results"][0]
    verdicts = {f["cve"]: f["verdict"] for f in result["findings"]}
    actual = verdicts.get(cve)
    exit_code = result["summary"]["exit_code"]
    ok = actual == expected and exit_code == expected_exit
    print("  %-12s %-16s %-18s exit=%d  %s" % (
        name, cve, actual, exit_code, "OK" if ok else "FAIL (expected %s, exit %d)" % (expected, expected_exit)
    ))
    failed = failed or not ok
if failed:
    raise SystemExit(1)
PY

echo "==> все интеграционные проверки прошли"
