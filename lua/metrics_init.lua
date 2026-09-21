local metrics = assert(ngx.shared.proxy_metrics, "proxy_metrics shared dict is required")

metrics:set("auth_failures", 0)
