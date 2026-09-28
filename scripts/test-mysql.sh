#!/usr/bin/env bash
# 使用一次性 MySQL 实例运行集成测试，数据目录和 Unix 套接字均位于专用临时目录。
# 实例关闭 TCP 监听；退出时只清理自己创建的进程与目录，不连接或修改宿主已有数据库。
set -euo pipefail
cd "$(dirname "$0")/.."
# 允许 Makefile 通过 GO 指定工具链；启动数据库前先确认必要命令存在。
authkit_go="${GO:-go}"
for tool in mysqld mysqladmin "$authkit_go"; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
# 每次运行使用独立路径，避免并行测试争用数据目录、套接字或日志文件。
authkit_tmp="$(mktemp -d /tmp/authkit-mysql.XXXXXX)"
authkit_socket="$authkit_tmp/mysql.sock"
authkit_pid=""
# 优先通过本实例的套接字正常关闭数据库，再等待退出；失败时才向记录的进程发送终止信号。
cleanup() {
  if [[ -n "$authkit_pid" ]]; then
    mysqladmin --no-defaults --protocol=socket --socket="$authkit_socket" --user=root shutdown >/dev/null 2>&1 || kill "$authkit_pid" 2>/dev/null || true
    wait "$authkit_pid" 2>/dev/null || true
  fi
  rm -rf "$authkit_tmp"
}
trap cleanup EXIT INT TERM
# --no-defaults 避免读取宿主数据库配置；无密码初始化仅用于这个隔离的临时实例。
mysqld --no-defaults --initialize-insecure --datadir="$authkit_tmp/data" >"$authkit_tmp/init.log" 2>&1 || { cat "$authkit_tmp/init.log" >&2; exit 1; }
mysqld --no-defaults --datadir="$authkit_tmp/data" --socket="$authkit_socket" --pid-file="$authkit_tmp/mysql.pid" --skip-networking --mysqlx=OFF --log-error="$authkit_tmp/mysql.log" &
authkit_pid=$!
ready=false
# 最多探测 150 次，每次间隔 0.2 秒；进程提前退出时立即结束等待并输出诊断日志。
for ((i=0; i<150; i++)); do
  if mysqladmin --no-defaults --protocol=socket --socket="$authkit_socket" --user=root ping >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$authkit_pid" 2>/dev/null; then break; fi
  sleep 0.2
done
if [[ "$ready" != true ]]; then cat "$authkit_tmp/mysql.log" >&2; exit 1; fi
# 连接信息仅传给本次 Go 测试；禁用测试缓存并启用竞态检测，真正执行数据库并发用例。
AUTHKIT_MYSQL_DSN="root@unix($authkit_socket)/?parseTime=true&loc=UTC" "$authkit_go" test -count=1 -race ./mysql/...
