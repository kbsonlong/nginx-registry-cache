local cjson = require "cjson.safe"
local crypto = require "crypto"
local secrets = require "secrets"

local dict = assert(ngx.shared.proxy_auth, "proxy_auth shared dict is required")
local cached_version, cached_snapshot
local json_null = cjson.null

local function decode_payload(payload)
    local decoded, err = cjson.decode(payload)
    if not decoded or type(decoded.version) ~= "number" or type(decoded.users) ~= "table" then
        return nil, err or "invalid snapshot payload"
    end
    local users = {}
    for _, user in ipairs(decoded.users) do
        if type(user.username) ~= "string" or type(user.id) ~= "string" or type(user.credentials) ~= "table" then
            return nil, "invalid snapshot user"
        end
        if user.expires_at == json_null then
            user.expires_at = nil
        end
        for _, credential in ipairs(user.credentials) do
            if credential.not_before == json_null then credential.not_before = nil end
            if credential.expires_at == json_null then credential.expires_at = nil end
            if credential.revoked_at == json_null then credential.revoked_at = nil end
        end
        users[user.username] = user
    end
    decoded.users_by_name = users
    return decoded
end

local function current()
    local version = dict:get("snapshot.version")
    local payload = dict:get("snapshot.payload")
    if not version or not payload then
        return nil, "snapshot_unavailable"
    end
    if cached_version == version then
        return cached_snapshot
    end
    local decoded, err = decode_payload(payload)
    if not decoded then
        return nil, err
    end
    cached_version, cached_snapshot = version, decoded
    return decoded
end

local function install(response_body)
    local envelope, err = cjson.decode(response_body)
    if not envelope or type(envelope.payload) ~= "string" or type(envelope.signature) ~= "string" then
        return nil, err or "invalid snapshot envelope"
    end
    local payload = ngx.decode_base64(envelope.payload)
    local key, key_err = secrets.snapshot_signing_key()
    if not payload or not key then
        return nil, key_err or "invalid snapshot payload encoding"
    end
    if not crypto.constant_time_equal(crypto.hmac_sha256_hex(key, payload), envelope.signature) then
        return nil, "invalid snapshot signature"
    end
    local decoded, decode_err = decode_payload(payload)
    if not decoded then
        return nil, decode_err
    end
    local current_version = tonumber(dict:get("snapshot.version")) or -1
    if decoded.version < current_version then
        return nil, "snapshot version regressed"
    end
    dict:set("snapshot.payload", payload)
    dict:set("snapshot.version", decoded.version)
    return true
end

return { current = current, install = install }
