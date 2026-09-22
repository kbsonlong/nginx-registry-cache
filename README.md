# OpenResty Registry Cache

这个配置验证两条独立链路，并保留认证与 metrics。正向代理凭据从只读挂载的
`htpasswd` 文件加载；每个文件条目都是一个独立用户：

```text
普通 HTTPS 请求
    -> 127.0.0.1:28080
    -> OpenResty CONNECT 正向代理

Registry pull
    -> 127.0.0.1:25443 (HTTPS)
    -> OpenResty 反向代理
    -> 重写 OSS 307 并缓存最终 blob 200
```

metrics 默认通过 `127.0.0.1:29145` 暴露；正向代理默认通过 `127.0.0.1:28080` 暴露。
管理 API 仅绑定在 `127.0.0.1:28081`，不会复用任何代理监听端口。

## 前置条件

- Colima 已启动并使用 Docker runtime。
- Docker、Docker Compose、curl、jq 可用。
- 本机 Docker/Colima 可以访问公网 Aliyun Registry；Docker pull 测试需要信任本地生成的证书。

## 运行

```bash
cd ~/Code/nginx_src/poc
docker compose up -d --build
./test.sh
```

默认宿主机端口为：正向代理 `28080`、HTTPS cache `25443`、metrics `29145`。如有冲突可在运行前覆盖：

```bash
PROXY_PORT=28080 CACHE_PORT=25443 METRICS_PORT=29145 ./test.sh
```

测试脚本会验证：

1. 构建产物为 OpenResty `1.27.1.2`，并包含 proxy-connect 模块；运行配置通过 `nginx -t`。
2. 未带 Proxy Token 的 HTTP 请求仍可到达上游，兼容生产存量未认证客户端。
3. `htpasswd` 中的 `proxy-user:proxy-token` 与 `proxy-reader:reader-token` 都可通过 CONNECT；显式错误凭据仍返回 407。
4. HTTPS Registry cache 仅通过容器内 443 暴露，旧 Registry 监听不再发布。
5. 管理面能创建用户与一次性 Token、禁用/启用用户、撤销 Token，并把签名快照发布给 OpenResty；每个变更均产生审计事件。
6. metrics 通过容器内 9145 暴露，认证失败计数可查询。
6. 可选执行冷拉取，验证 OSS blob 首次 MISS、再次 HIT。

测试不依赖 Docker Hub 或公网 DNS。默认 `./test.sh` 会重建镜像；排查运行中容器时可用 `BUILD=0 ./test.sh` 跳过重建。

## 手工检查

正向代理：

```bash
curl -v -x http://127.0.0.1:28080 https://registry-1.docker.io/v2/
curl -v -x http://proxy-user:proxy-token@127.0.0.1:28080 https://registry-1.docker.io/v2/
curl -v -x http://proxy-reader:reader-token@127.0.0.1:28080 https://registry-1.docker.io/v2/
```

## 正向代理用户文件

Compose 将本目录的 `htpasswd.example` 只读挂载到
`/etc/openresty/auth/htpasswd`。它是两个演示用户的 fixture；生产环境请以同一路径
挂载由 Secret 管理的文件，不要把实际凭据复制进镜像或提交到仓库。服务每 5 秒重新
读取该文件，因此以原子替换文件的方式更新用户无需重建镜像。

兼容文件仅用于迁移期，使用 Apache SHA 创建：

```bash
htpasswd -sbn proxy-user 'replace-with-a-token' > htpasswd
htpasswd -sbn proxy-reader 'replace-with-another-token' >> htpasswd
```

认证代码支持 `{SHA}` 和 `{SSHA}` 格式；该兼容适配器不接受明文、bcrypt 或 crypt 格式。
生产环境应使用下文控制面生成的 HMAC-SHA-256 Token 快照，而不是继续依赖该文件。

## 管理控制面

`proxy-admin` 是一个独立的 FastAPI/SQLite POC 服务，实现设计文档第 8.4 节的用户、
Token、禁用/启用和审计接口，并在 `http://127.0.0.1:28081/` 提供静态 HTML 管理页。它用 `HMAC-SHA-256(pepper, token)` 保存凭据摘要；Token
仅在 `POST /v1/users/{id}/tokens` 的响应中返回一次。每次用户或 Token 变更都会推进
快照版本，并发布 `{payload, signature}`；OpenResty 每 5 秒在内部 Docker 网络拉取、验证
HMAC-SHA-256 签名后才接受新版快照。

本地 POC 的四个 `secrets.example/*` 文件是可复现测试 fixture，启动前必须替换为 Secret
管理系统提供的只读文件。生产环境不得提交它们、不得通过环境变量传递真实值，并且管理
API 应置于独立管理网络，而不是仅依赖 compose 的 loopback 端口绑定。

示例：

```bash
admin_token="$(tr -d '\r\n' < secrets.example/admin-api-token)"
admin_url=http://127.0.0.1:28081
headers=(-H "Authorization: Bearer $admin_token" -H 'X-Actor: operator' -H 'X-Request-ID: change-123')

user_id="$(curl -fsS "${headers[@]}" -H 'Content-Type: application/json' \
  -d '{"username":"build-runner"}' "$admin_url/v1/users" | jq -r .id)"
token="$(curl -fsS "${headers[@]}" -H 'Content-Type: application/json' -d '{}' \
  "$admin_url/v1/users/$user_id/tokens" | jq -r .token)"
curl -v -x "http://build-runner:$token@127.0.0.1:28080" https://registry-1.docker.io/v2/

# 轮换后确认客户端已切换，再撤销旧 Token；禁用可立即在下一个快照周期生效。
curl -fsS "${headers[@]}" -X POST -H 'Content-Type: application/json' -d '{}' \
  "$admin_url/v1/users/$user_id/disable"
curl -fsS "${headers[@]}" "$admin_url/v1/audit-events?limit=20" | jq
```

在迁移期间，未被控制面快照声明的用户名仍会回退到挂载的 `htpasswd` 文件。只要同名用户
进入快照，快照中的禁用、过期和撤销状态优先，不能由 `htpasswd` 绕过。生产切到
`required` 模式前必须移除这一兼容后备，并完成设计文档第 8.8 节的三态和豁免实现。

HTTPS Registry cache：

```bash
curl -k -i https://127.0.0.1:25443/v2/
curl -k -i https://127.0.0.1:25443/v2/seam/kubectl/manifests/latest
```

metrics：

```bash
curl -i http://127.0.0.1:29145/metrics
```

## Docker pull 方式

测试 Aliyun Registry cache：

```bash
docker pull 127.0.0.1:25443/seam/kubectl
```

生产形态的 HTTPS 入口为 `25443`，客户端到 OpenResty 和 OpenResty 到 Aliyun 均使用 TLS。上游返回的 OSS `307` 会被 Nginx 重写到本地签名路径，再由 Nginx 拉取并缓存最终 `200` blob。

```bash
curl -k -i https://127.0.0.1:25443/v2/
curl -k -i https://127.0.0.1:25443/v2/seam/kubectl/manifests/latest
```

要让 Docker/Colima 直接 pull HTTPS 入口，先导出并信任证书：

```bash
docker cp "$(docker compose ps -q proxy):/etc/openresty/certs/tls-origin.crt" ./registry-cache.crt
```

然后将 `registry-cache.crt` 安装到 Docker/Colima 的 Registry CA 信任目录，再使用：

```bash
docker pull 127.0.0.1:25443/seam/kubectl
```

首次拉取会访问 OSS 并写入 Nginx cache，后续请求可直接命中 Nginx 磁盘缓存。生产环境应使用正式证书、受限的 OSS 域名白名单和独立 cache 存储卷。

## Docker registry mirror

### Docker Engine

Docker Engine 的 `registry-mirrors` 只对 Docker Hub 的默认 Registry 生效，不能
把任意 `registry.cn-hangzhou.aliyuncs.com/...` 镜像自动改写到缓存。Docker daemon
配置示例：

```json
{
  "registry-mirrors": [
    "https://image-cache.k8s-cluster.kbsonlong.com"
  ]
}
```

将 `image-cache.k8s-cluster.kbsonlong.com` 替换为已经配置正式证书的 443 cache 域名，然后重启
Docker daemon。Linux Engine 通常修改 `/etc/docker/daemon.json` 后执行：

```bash
sudo systemctl restart docker
```

Colima 把 Docker daemon 运行在 VM 内，可在 `~/.colima/default/colima.yaml` 中配置：

```yaml
env:
  NO_PROXY: localhost,127.0.0.1,.example.com
```

如果使用显式 cache 域名，直接将镜像引用改成该域名，例如：

```bash
docker pull image-cache.k8s-cluster.kbsonlong.com/seam/kubectl:latest
```

缓存域名的证书必须被 Docker daemon 信任；不要在 `registry-mirrors` URL 中写账号密码。
公开 mirror 不需要 `docker login`。只有当 mirror 本身要求认证，或使用
`docker pull <cache-host>/...` 直接把 cache 域名当作 Registry 时，才需要：

```bash
docker login image-cache.k8s-cluster.kbsonlong.com
```

私有 Aliyun Registry 则按镜像引用和上游返回的认证挑战登录对应 Registry；cache
应只转发 `Authorization`/`WWW-Authenticate`，不在 mirror URL 中保存凭据。

例如直接使用远端 Registry：

```bash
docker login registry.cn-hangzhou.aliyuncs.com
docker pull registry.cn-hangzhou.aliyuncs.com/seam/kubectl:latest
```

其他远端域名同理，登录的主机名必须和镜像引用中的 Registry 主机名一致：

```bash
docker login registry.ap-southeast-1.aliyuncs.com
docker login sl-repo-sg-registry.ap-southeast-1.cr.aliyuncs.com
```

如果镜像引用改成 cache 域名，则登录 cache 域名而不是远端域名：

```bash
docker login image-cache.example.com
docker pull image-cache.example.com/seam/kubectl:latest
```

通过 HTTP/HTTPS proxy 拉取时，Registry 登录凭据仍在 TLS 隧道内发送；proxy
认证凭据和 Registry 登录凭据是两套独立配置。

### containerd

containerd 使用 `hosts.toml` 配置 Registry mirror。先在
`/etc/containerd/config.toml` 启用 hosts 目录：

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"
```

为每个原始 Registry 建立同名目录，例如
`/etc/containerd/certs.d/registry.cn-hangzhou.aliyuncs.com/hosts.toml`：

```toml
server = "https://registry.cn-hangzhou.aliyuncs.com"

[host."https://image-cache.k8s-cluster.kbsonlong.com"]
  capabilities = ["pull", "resolve"]
```

其他 Registry 使用相同格式，将目录名和 `server` 改成对应的上游域名：

```text
/etc/containerd/certs.d/registry.ap-southeast-1.aliyuncs.com/hosts.toml
/etc/containerd/certs.d/registry.ap-southeast-5.aliyuncs.com/hosts.toml
```

修改后重启 containerd：

```bash
sudo systemctl restart containerd
```

如果 cache 使用独立域名，Nginx 必须能从该域名判断原始 Registry，或者为每个
Registry 配置独立的 TLS/Host 入口；不能把所有上游都发送到一个未配置路由的
通用域名。公开 mirror 不需要凭据；私有仓库凭据应通过 containerd 的 credential helper 或节点运行时配置
管理，不要提交到 `hosts.toml`。

## 当前监听与缓存边界

配置只发布三个端口：`8080` 正向代理、`443` HTTPS Aliyun cache、`9145` metrics。
旧的本地 Registry、origin 和 Registry cache 监听已删除。443 入口只允许以下
Registry 上游：

```text
registry.ap-southeast-1.aliyuncs.com
registry.ap-southeast-5.aliyuncs.com
registry.cn-hangzhou.aliyuncs.com
```

Registry 返回的 OSS `307` 会被重写为受限的 `aliyuncs.com` 路径，由 Nginx
自己缓存最终 `200` blob；未列出的 Host 返回 444。

注意事项：

- `registry-mirrors` 主要用于 Docker Hub，不能自动把任意 `registry.cn-hangzhou.aliyuncs.com` 改写到缓存；测试时使用显式的 `127.0.0.1:25443` 入口。
- 如果使用原域名透明接入，NGINX 必须终止 TLS，证书 SAN 必须包含原域名；Docker/containerd 还必须信任该证书。否则采用 `aliyun-registry-cache.example.com` 这类独立域名，并修改镜像引用。
- `seam/kubectl` 若是私有仓库，不能使用不带凭据隔离的全局 digest 缓存。上面示例把 `Authorization` 纳入 key；更高安全等级应在缓存前增加 auth gateway/租户隔离。
- 正向代理只负责公网 CONNECT，不参与上述 Registry blob 缓存；不要把 Registry mirror 指向 `28080` 正向代理端口。

## 清理

只删除本配置创建的 Compose 容器、网络和卷：

```bash
docker compose down -v
```

该命令会删除本配置的 `aliyun-blob-cache` 卷，不会删除其他 Docker 镜像或 Colima profile。

## 已知边界

- 这是本地 arm64 验证环境，不代表生产环境的 OpenResty、模块、磁盘和网络性能已验收。
- 本目录是新数据面的隔离配置；仓库中的 `log_proxy/` 与 `registry-cache/` 两套旧配置没有被覆盖或改写。它们的端口/路径兼容性仍应按主设计文档第 16.7 节单独执行 `nginx -t`、端口和流量回归。
- 当前使用环境变量中的静态 Basic Token，不是生产级用户管理实现。
- 当前指标中的 bytes 是 NGINX `$bytes_sent`，不等同于 CONNECT 隧道双向 payload 的精确字节；生产需要 proxy-connect 字节计数扩展。
- 当前只缓存完整 `200` blob 响应，未启用 `206 Range` 分片缓存。
- 当前已覆盖 Aliyun Registry 返回 OSS 重定向的路径；生产仍应使用正式证书、受限的 OSS 域名白名单和独立缓存存储。
