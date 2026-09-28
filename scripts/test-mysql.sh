#!/usr/bin/env bash
# Run integration tests against a disposable Unix-socket-only MySQL instance.
set -euo pipefail
cd "$(dirname "$0")/.."
authkit_go="${GO:-go}"
for tool in mysqld mysqladmin "$authkit_go"; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
authkit_tmp="$(mktemp -d /tmp/authkit-mysql.XXXXXX)"
authkit_socket="$authkit_tmp/mysql.sock"
authkit_pid=""
cleanup() {
  if [[ -n "$authkit_pid" ]]; then
    mysqladmin --no-defaults --protocol=socket --socket="$authkit_socket" --user=root shutdown >/dev/null 2>&1 || kill "$authkit_pid" 2>/dev/null || true
    wait "$authkit_pid" 2>/dev/null || true
  fi
  rm -rf "$authkit_tmp"
}
trap cleanup EXIT INT TERM
mysqld --no-defaults --initialize-insecure --datadir="$authkit_tmp/data" >"$authkit_tmp/init.log" 2>&1 || { cat "$authkit_tmp/init.log" >&2; exit 1; }
mysqld --no-defaults --datadir="$authkit_tmp/data" --socket="$authkit_socket" --pid-file="$authkit_tmp/mysql.pid" --skip-networking --mysqlx=OFF --log-error="$authkit_tmp/mysql.log" &
authkit_pid=$!
ready=false
for ((i=0; i<150; i++)); do
  if mysqladmin --no-defaults --protocol=socket --socket="$authkit_socket" --user=root ping >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$authkit_pid" 2>/dev/null; then break; fi
  sleep 0.2
done
if [[ "$ready" != true ]]; then cat "$authkit_tmp/mysql.log" >&2; exit 1; fi
AUTHKIT_MYSQL_DSN="root@unix($authkit_socket)/?parseTime=true&loc=UTC" "$authkit_go" test -count=1 -race ./mysql/...
