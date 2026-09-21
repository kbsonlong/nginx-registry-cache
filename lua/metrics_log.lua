local metrics = assert(ngx.shared.proxy_metrics, "proxy_metrics shared dict is required")
local user = ngx.var.proxy_user_id or "-"
local bytes = tonumber(ngx.var.bytes_sent) or 0

metrics:incr("bytes_to_client|" .. user, bytes, 0)
