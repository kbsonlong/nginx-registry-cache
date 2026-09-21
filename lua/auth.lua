-- This POC keeps unauthenticated requests compatible with existing clients.
-- When credentials are supplied, validate them against the mounted htpasswd
-- file and return the standard proxy-authentication challenge on failure.
local HTPASSWD_FILE = "/etc/openresty/auth/htpasswd"
local CACHE_KEY = "htpasswd.contents"
local CACHE_TTL_SECONDS = 5

local metrics = assert(ngx.shared.proxy_metrics, "proxy_metrics shared dict is required")
local auth_cache = assert(ngx.shared.proxy_auth, "proxy_auth shared dict is required")

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

    -- ngx.crypt delegates bcrypt, SHA-crypt, Apache MD5 and legacy crypt
    -- formats to the image's libcrypt implementation.
    if password_hash:sub(1, 1) == "$" or password_hash:sub(1, 1) == "_" then
        local derived = ngx.crypt(password, password_hash)
        return derived and constant_time_equal(derived, password_hash) or false
    end

    -- `htpasswd -p` stores a literal password. It is accepted for local
    -- compatibility only; production files must use a one-way hash.
    return constant_time_equal(password, password_hash)
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
local username, password = decoded and decoded:match("^([^:]+):(.*)$")
if not username then
    return reject("invalid")
end

local users = load_users()
if not users then
    return unavailable()
end

if not password_matches(password, users[username]) then
    return reject("invalid")
end

ngx.var.proxy_user_id = username
increment("requests_total|" .. username)
