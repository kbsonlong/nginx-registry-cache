local snapshot = require "snapshot"
local secrets = require "secrets"

local function fetch(premature)
    if premature then
        return
    end
    local access_token, secret_err = secrets.snapshot_access_token()
    if not access_token then
        ngx.log(ngx.ERR, "snapshot access token unavailable: ", secret_err)
        return
    end
    local socket = ngx.socket.tcp()
    socket:settimeout(2000)
    local ok, connect_err = socket:connect("proxy-admin", 8081)
    if not ok then
        ngx.log(ngx.WARN, "snapshot fetch connect failed: ", connect_err)
        return
    end
    local request = "GET /v1/snapshot HTTP/1.1\r\nHost: proxy-admin\r\nConnection: close\r\n"
        .. "X-Proxy-Snapshot-Token: " .. access_token .. "\r\n\r\n"
    local sent, send_err = socket:send(request)
    if not sent then
        ngx.log(ngx.WARN, "snapshot fetch send failed: ", send_err)
        return
    end
    local response, receive_err, partial = socket:receive("*a")
    response = response or partial
    if not response then
        ngx.log(ngx.WARN, "snapshot fetch receive failed: ", receive_err)
        return
    end
    local header_end = response:find("\r\n\r\n", 1, true)
    if not header_end or not response:find("^HTTP/1%.[01] 200 ") then
        ngx.log(ngx.WARN, "snapshot fetch returned non-200 response")
        return
    end
    local ok_install, install_err = snapshot.install(response:sub(header_end + 4))
    if not ok_install then
        ngx.log(ngx.ERR, "snapshot rejected: ", install_err)
    end
end

local function schedule(premature)
    fetch(premature)
    if not premature then
        local ok, err = ngx.timer.at(5, schedule)
        if not ok then
            ngx.log(ngx.ERR, "unable to schedule snapshot refresh: ", err)
        end
    end
end

local ok, err = ngx.timer.at(0, schedule)
if not ok then
    ngx.log(ngx.ERR, "unable to start snapshot refresh: ", err)
end
