-- Self-contained SHA-256/HMAC-SHA-256 implementation for the snapshot
-- contract.  It avoids runtime package downloads and keeps the OpenResty
-- image's cryptographic dependency surface explicit.
local bit = require "bit"
local band, bor, bxor, bnot, rshift, ror, tobit =
    bit.band, bit.bor, bit.bxor, bit.bnot, bit.rshift, bit.ror, bit.tobit

local constants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function add(...)
    local total = 0
    for index = 1, select("#", ...) do
        total = total + select(index, ...)
    end
    return tobit(total)
end

local function big_endian_word(value)
    return string.char(
        band(rshift(value, 24), 0xff), band(rshift(value, 16), 0xff),
        band(rshift(value, 8), 0xff), band(value, 0xff)
    )
end

local function sha256_bin(message)
    local length = #message
    local bits = length * 8
    local high = math.floor(bits / 4294967296)
    local low = bits % 4294967296
    local padding = (56 - (length + 1) % 64) % 64
    message = message .. "\128" .. string.rep("\0", padding) .. big_endian_word(high) .. big_endian_word(low)

    local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    for offset = 1, #message, 64 do
        local words = {}
        for index = 0, 15 do
            local start = offset + index * 4
            words[index] = bor(
                bit.lshift(message:byte(start), 24), bit.lshift(message:byte(start + 1), 16),
                bit.lshift(message:byte(start + 2), 8), message:byte(start + 3)
            )
        end
        for index = 16, 63 do
            local x, y = words[index - 15], words[index - 2]
            local s0 = bxor(ror(x, 7), ror(x, 18), rshift(x, 3))
            local s1 = bxor(ror(y, 17), ror(y, 19), rshift(y, 10))
            words[index] = add(words[index - 16], s0, words[index - 7], s1)
        end

        local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for index = 0, 63 do
            local s1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
            local choice = bxor(band(e, f), band(bnot(e), g))
            local temp1 = add(h, s1, choice, constants[index + 1], words[index])
            local s0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
            local majority = bxor(band(a, b), band(a, c), band(b, c))
            local temp2 = add(s0, majority)
            h, g, f, e, d, c, b, a = g, f, e, add(d, temp1), c, b, a, add(temp1, temp2)
        end
        h0, h1, h2, h3 = add(h0, a), add(h1, b), add(h2, c), add(h3, d)
        h4, h5, h6, h7 = add(h4, e), add(h5, f), add(h6, g), add(h7, h)
    end

    return big_endian_word(h0) .. big_endian_word(h1) .. big_endian_word(h2) .. big_endian_word(h3)
        .. big_endian_word(h4) .. big_endian_word(h5) .. big_endian_word(h6) .. big_endian_word(h7)
end

local function hmac_sha256_hex(key, message)
    if type(key) ~= "string" or type(message) ~= "string" then
        return nil, "HMAC key and message must be strings"
    end
    if #key > 64 then
        key = sha256_bin(key)
    end
    key = key .. string.rep("\0", 64 - #key)
    local outer, inner = {}, {}
    for index = 1, 64 do
        local byte = key:byte(index)
        outer[index] = string.char(bxor(byte, 0x5c))
        inner[index] = string.char(bxor(byte, 0x36))
    end
    return (sha256_bin(table.concat(outer) .. sha256_bin(table.concat(inner) .. message)):gsub(".", function(byte)
        return string.format("%02x", byte:byte())
    end))
end

local function constant_time_equal(left, right)
    if type(left) ~= "string" or type(right) ~= "string" or #left ~= #right then
        return false
    end
    local difference = 0
    for index = 1, #left do
        difference = bor(difference, bxor(left:byte(index), right:byte(index)))
    end
    return difference == 0
end

return {
    hmac_sha256_hex = hmac_sha256_hex,
    constant_time_equal = constant_time_equal,
}
