-- This POC keeps unauthenticated requests compatible with existing clients.
-- When credentials are supplied, validate them against the mounted htpasswd
-- file and return the standard proxy-authentication challenge on failure.
local HTPASSWD_FILE = "/etc/openresty/auth/htpasswd"
local CACHE_KEY = "htpasswd.contents"
local CACHE_TTL_SECONDS = 5

local metrics = assert(ngx.shared.proxy_metrics, "proxy_metrics shared dict is required")
local auth_cache = assert(ngx.shared.proxy_auth, "proxy_auth shared dict is required")
local crypto = require "crypto"
local secrets = require "secrets"
local snapshot = require "snapshot"

local function increment(key)
    metrics:incr(key, 1, 0)
end

local function reject(reason)
    increment("auth_failures")
    increment("auth_failure_" .. reason)
    ngx.header["Proxy-Authenticate"] = 'Basic realm="forward-proxy"'
    ngx.header["Cache-Control"] = "no-store"
    return ngx.exit(407)
end

local function unavailable()
    increment("auth_failures")
    increment("auth_failure_unavailable")
    ngx.log(ngx.ERR, "unable to load htpasswd authentication file: ", HTPASSWD_FILE)
    return ngx.exit(503)
end

local function load_users()
    local contents = auth_cache:get(CACHE_KEY)
    if not contents then
        local file, err = io.open(HTPASSWD_FILE, "r")
        if not file then
            return nil, err
        end

        contents = file:read("*a")
        file:close()
        if not contents then
            return nil, "unable to read file"
        end

        auth_cache:set(CACHE_KEY, contents, CACHE_TTL_SECONDS)
    end

    local users = {}
    for line in contents:gmatch("[^\r\n]+") do
        if not line:match("^%s*#") and not line:match("^%s*$") then
            local username, password_hash = line:match("^([^:]+):(.+)$")
            if username and password_hash then
                users[username] = password_hash
            else
                return nil, "invalid htpasswd entry"
            end
        end
    end

    if not next(users) then
        return nil, "no usable htpasswd entries"
    end

    return users
end

local function constant_time_equal(left, right)
    if type(left) ~= "string" or type(right) ~= "string" or #left ~= #right then
        return false
    end

    local difference = 0
    for index = 1, #left do
        difference = bit.bor(difference, bit.bxor(left:byte(index), right:byte(index)))
    end
    return difference == 0
end

local function password_matches(password, password_hash)
    if password_hash:sub(1, 5) == "{SHA}" then
        return constant_time_equal(ngx.encode_base64(ngx.sha1_bin(password)), password_hash:sub(6))
    end

    if password_hash:sub(1, 6) == "{SSHA}" then
        local digest_and_salt = ngx.decode_base64(password_hash:sub(7))
        if not digest_and_salt or #digest_and_salt < 20 then
            return false
        end
        local expected_digest = digest_and_salt:sub(1, 20)
        local salt = digest_and_salt:sub(21)
        return constant_time_equal(ngx.sha1_bin(password .. salt), expected_digest)
    end

    if password_hash:sub(1, 7) == "{PLAIN}" then
        return constant_time_equal(password, password_hash:sub(8))
    end

    -- The file adapter intentionally supports the portable htpasswd formats
    -- above only. Production traffic uses the control-plane HMAC-SHA-256
    -- snapshot path; never place a literal password in this compatibility file.
    return false
end

local function snapshot_user_id(username, token)
    -- Never allow an unexpected request-header representation to turn an
    -- authentication failure into a worker error / HTTP 500.
    if type(username) ~= "string" or type(token) ~= "string" then
        return false, "invalid"
    end
    local current = snapshot.current()
    if not current then
        -- The local htpasswd backend remains a POC compatibility fallback
        -- until every client has been migrated to the control plane.
        return nil
    end

    local user = current.users_by_name[username]
    if not user then
        return nil
    end

    if user.status ~= "active" then
        return false, "disabled"
    end
    local now = os.date("!%Y-%m-%dT%H:%M:%SZ")
    if user.expires_at and user.expires_at <= now then
        return false, "expired"
    end

    local pepper, pepper_err = secrets.auth_pepper()
    if not pepper then
        ngx.log(ngx.ERR, "authentication pepper unavailable: ", pepper_err)
        return false, "unavailable"
    end
    local digest = crypto.hmac_sha256_hex(pepper, token)
    local expired = false
    for _, credential in ipairs(user.credentials) do
        if not credential.revoked_at then
            if (credential.not_before and credential.not_before > now)
                or (credential.expires_at and credential.expires_at <= now) then
                expired = true
            elseif crypto.constant_time_equal(digest, credential.token_digest) then
                return user.id
            end
        end
    end
    return false, expired and "expired" or "invalid"
end

local header = ngx.req.get_headers()["proxy-authorization"]
if type(header) == "table" then
    header = header[1]
end

if not header then
    ngx.var.proxy_user_id = "-"
    increment("requests_total|-")
    return
end

local encoded = header:match("^[Bb]asic%s+(.+)$")
if not encoded then
    return reject("scheme")
end

local decoded = ngx.decode_base64(encoded)
local separator = decoded and decoded:find(":", 1, true)
if not separator or separator == 1 then
    return reject("invalid")
end
local username = decoded:sub(1, separator - 1)
local password = decoded:sub(separator + 1)

local managed_user_id, managed_result = snapshot_user_id(username, password)
if managed_user_id then
    ngx.var.proxy_user_id = managed_user_id
    increment("requests_total|" .. managed_user_id)
    return
end
if managed_result then
    if managed_result == "unavailable" then
        return unavailable()
    end
    return reject(managed_result)
end

local users = load_users()
if not users then
    return unavailable()
end

local password_hash = users[username]
if not password_hash or not password_matches(password, password_hash) then
    return reject("invalid")
end

ngx.var.proxy_user_id = username
increment("requests_total|" .. username)
