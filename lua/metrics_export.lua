local metrics = assert(ngx.shared.proxy_metrics, "proxy_metrics shared dict is required")

local function prometheus_label(value)
    return value:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n")
end

ngx.header.content_type = "text/plain; version=0.0.4"
ngx.say("# TYPE forward_proxy_requests_total counter")
ngx.say("# TYPE forward_proxy_auth_failures_total counter")
ngx.say("# TYPE forward_proxy_bytes_to_client_total counter")

for _, key in ipairs(metrics:get_keys(1000)) do
    local value = metrics:get(key) or 0
    local user = key:match("^requests_total|(.+)$")
    if user then
        ngx.say('forward_proxy_requests_total{user_id="', prometheus_label(user), '"} ', value)
    end

    local bytes_user = key:match("^bytes_to_client|(.+)$")
    if bytes_user then
        ngx.say('forward_proxy_bytes_to_client_total{user_id="', prometheus_label(bytes_user), '"} ', value)
    end
end

ngx.say("forward_proxy_auth_failures_total ", metrics:get("auth_failures") or 0)
