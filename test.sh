#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$WORK_DIR"

COMPOSE=(docker compose -f docker-compose.yml)
BUILD="${BUILD:-1}"
PROXY_PORT="${PROXY_PORT:-28080}"
CACHE_PORT="${CACHE_PORT:-25443}"
METRICS_PORT="${METRICS_PORT:-29145}"
ADMIN_PORT="${ADMIN_PORT:-28081}"
PROXY="http://proxy-user:proxy-token@127.0.0.1:${PROXY_PORT}"
READER_PROXY="http://proxy-reader:reader-token@127.0.0.1:${PROXY_PORT}"
CACHE="https://127.0.0.1:${CACHE_PORT}"
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"
ADMIN_TOKEN="$(tr -d '\r\n' < secrets.example/admin-api-token)"
UPSTREAM="https://registry.cn-hangzhou.aliyuncs.com/v2/"
REGISTRY_HOSTS=(
    registry.ap-southeast-1.aliyuncs.com
    registry.ap-southeast-5.aliyuncs.com
    registry.cn-hangzhou.aliyuncs.com
    sl-repo-sg-registry.ap-southeast-1.cr.aliyuncs.com
    sl-repo-sz-registry.cn-shenzhen.cr.aliyuncs.com
    yy-repo-hz-registry.cn-hangzhou.cr.aliyuncs.com
    yy-repo-sg-registry.ap-southeast-1.cr.aliyuncs.com
)

if [[ "$BUILD" = "1" ]]; then
    echo "== build and start =="
    "${COMPOSE[@]}" up -d --build --force-recreate --remove-orphans proxy
else
    echo "== start existing image (BUILD=0) =="
    "${COMPOSE[@]}" up -d --no-build --remove-orphans proxy
fi

echo "== OpenResty and proxy-connect build contract =="
nginx_version="$(${COMPOSE[@]} exec -T proxy /usr/local/openresty/nginx/sbin/nginx -V 2>&1)"
grep -Fq 'nginx version: openresty/1.27.1.2' <<<"$nginx_version"
grep -Fq -- '--add-module=/src/proxy-connect' <<<"$nginx_version"
"${COMPOSE[@]}" exec -T proxy /usr/local/openresty/nginx/sbin/nginx \
    -t -p /etc/openresty -c /etc/openresty/nginx.conf

echo "== proxy, cache, metrics, and loopback-only management API are published =="
ports="$(${COMPOSE[@]} ps --format '{{.Ports}}')"
grep -Fq -- '->8080/tcp' <<<"$ports"
grep -Fq -- '->443/tcp' <<<"$ports"
grep -Fq -- '->9145/tcp' <<<"$ports"
grep -Fq -- '127.0.0.1:' <<<"$ports"
grep -Fq -- '->8081/tcp' <<<"$ports"
! grep -Eq -- '->(5001|5003|5443)/tcp' <<<"$ports"

echo "== control-plane lifecycle publishes signed snapshots =="
for attempt in {1..15}; do
    if curl -fsS "$ADMIN_URL/healthz" | jq -e '.status == "ok"' >/dev/null; then
        break
    fi
    test "$attempt" -lt 15
    sleep 1
done

admin_headers=(
    -H "Authorization: Bearer $ADMIN_TOKEN"
    -H "X-Actor: poc-test"
    -H "X-Request-ID: control-plane-test"
)
users="$(curl -fsS "${admin_headers[@]}" "$ADMIN_URL/v1/users")"
control_user_id="$(jq -r '.items[] | select(.username == "control-plane-test") | .id' <<<"$users")"
if [[ -z "$control_user_id" ]]; then
    control_user_id="$(curl -fsS "${admin_headers[@]}" -H 'Content-Type: application/json' \
        -d '{"username":"control-plane-test"}' "$ADMIN_URL/v1/users" | jq -r '.id')"
fi
control_token="$(curl -fsS "${admin_headers[@]}" -H 'Content-Type: application/json' -d '{}' \
    "$ADMIN_URL/v1/users/$control_user_id/tokens" | jq -r '.token')"
control_proxy="http://control-plane-test:${control_token}@127.0.0.1:${PROXY_PORT}"

expect_proxy_status() {
    local expected="$1"
    local actual=""
    for attempt in {1..15}; do
        actual="$(curl -ksS -o /dev/null -w '%{http_code}' -x "$control_proxy" "$UPSTREAM" || true)"
        if [[ "$actual" = "$expected" ]]; then
            return
        fi
        sleep 1
    done
    echo "expected proxy status $expected, got $actual" >&2
    return 1
}

expect_proxy_status 401
curl -fsS "${admin_headers[@]}" -X POST -H 'Content-Type: application/json' -d '{}' \
    "$ADMIN_URL/v1/users/$control_user_id/disable" | jq -e '.status == "disabled"' >/dev/null
expect_proxy_status 407
curl -fsS "${admin_headers[@]}" -X POST -H 'Content-Type: application/json' -d '{}' \
    "$ADMIN_URL/v1/users/$control_user_id/enable" | jq -e '.status == "active"' >/dev/null
expect_proxy_status 401
control_token_id="$(curl -fsS "${admin_headers[@]}" "$ADMIN_URL/v1/users/$control_user_id" | jq -r '.tokens[-1].id')"
curl -fsS "${admin_headers[@]}" -X DELETE "$ADMIN_URL/v1/users/$control_user_id/tokens/$control_token_id" \
    -o /dev/null -w '%{http_code}' | grep -Fx 204
expect_proxy_status 407
curl -fsS "${admin_headers[@]}" "$ADMIN_URL/v1/audit-events?limit=10" \
    | jq -e '.items[] | select(.request_id == "control-plane-test")' >/dev/null

echo "== HTTPS Registry cache is reachable =="
cache_status="$(curl -ksS -o /dev/null -w '%{http_code}' "$CACHE/v2/")"
test "$cache_status" = 401
for registry_host in "${REGISTRY_HOSTS[@]}"; do
    host_status="$(curl -ksS --resolve "${registry_host}:${CACHE_PORT}:127.0.0.1" \
        -o /dev/null -w '%{http_code}' "https://${registry_host}:${CACHE_PORT}/v2/")"
    test "$host_status" = 401
done

echo "== unauthenticated CONNECT remains allowed =="
unauthenticated_status="$(curl -ksS -o /dev/null -w '%{http_code}' \
    -x "http://127.0.0.1:${PROXY_PORT}" "$UPSTREAM")"
test "$unauthenticated_status" = 401

echo "== invalid credentials are still rejected =="
invalid_headers="$(mktemp)"
curl -sS -D "$invalid_headers" -o /dev/null \
    -x "http://bad-user:bad-token@127.0.0.1:${PROXY_PORT}" "$UPSTREAM" || true
grep -Eq '^HTTP/[0-9.]+ 407([[:space:]]|$)' "$invalid_headers"
grep -qi '^Proxy-Authenticate: Basic realm="forward-proxy"' "$invalid_headers"
grep -qi '^Cache-Control: no-store' "$invalid_headers"

echo "== authenticated CONNECT reaches Registry upstream =="
status="$(curl -ksS -o /dev/null -w '%{http_code}' \
    -x "$PROXY" "$UPSTREAM")"
test "$status" = 401

echo "== a second htpasswd user is also accepted =="
reader_status="$(curl -ksS -o /dev/null -w '%{http_code}' \
    -x "$READER_PROXY" "$UPSTREAM")"
test "$reader_status" = 401

echo "== metrics remains reachable =="
metrics_status="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${METRICS_PORT}/metrics")"
test "$metrics_status" = 200

echo "== optional cold pull cache test =="
if [[ "${PULL_TEST:-0}" = "1" ]]; then
    image="127.0.0.1:${CACHE_PORT}/seam/kubectl:latest"
    docker image rm "$image" >/dev/null 2>&1 || true
    docker pull "$image"
    first_logs="$(${COMPOSE[@]} logs --no-color --tail=100 proxy)"
    grep -Eq '"request":"GET /_aliyun_oss/.*".*"upstream_cache_status":"(MISS|HIT)"' <<<"$first_logs"
    docker image rm "$image" >/dev/null 2>&1 || true
    docker pull "$image"
    second_logs="$(${COMPOSE[@]} logs --no-color --tail=100 proxy)"
    grep -Eq '"request":"GET /_aliyun_oss/.*".*"upstream_cache_status":"HIT"' <<<"$second_logs"
    echo "HTTPS blob cache: HIT verified"
else
    echo "skipped (set PULL_TEST=1 after clearing aliyun-blob-cache)"
fi

rm -f "$invalid_headers"
echo "PASS"
