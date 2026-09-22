local cache = {}

local function read(path)
    if cache[path] then
        return cache[path]
    end
    local file, err = io.open(path, "r")
    if not file then
        return nil, err
    end
    local value = file:read("*a")
    file:close()
    value = value and value:gsub("%s+$", "")
    if not value or value == "" then
        return nil, "secret is empty"
    end
    cache[path] = value
    return value
end

return {
    auth_pepper = function() return read("/etc/openresty/secrets/auth-pepper") end,
    snapshot_access_token = function() return read("/etc/openresty/secrets/snapshot-access-token") end,
    snapshot_signing_key = function() return read("/etc/openresty/secrets/snapshot-signing-key") end,
}
