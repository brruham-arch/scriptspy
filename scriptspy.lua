-- ScriptSpy Companion v1.0
-- Monitor dan kontrol libscriptspy.so dari dalam game
-- MoNetLoader / MoonLoader Android
-- by brruham-arch

local ffi = require "ffi"

ffi.cdef[[
    typedef struct {
        void (*enable)(void);
        void (*disable)(void);
        int  (*is_on)(void);
        int  (*count)(void);
    } ScriptSpyAPI;
]]

local COLOR_OK    = 0x44FF44
local COLOR_ERR   = 0xFF4444
local COLOR_INFO  = 0xFFFF44
local PREFIX      = "[ScriptSpy]"

local api = nil

local function msg(text, color)
    sampAddChatMessage(PREFIX .. " " .. text, color or 0xFFFFFF)
end

local function loadAPI()
    local f = io.open("/storage/emulated/0/scriptspy_addr.txt", "r")
    if not f then
        msg("ERROR: scriptspy_addr.txt tidak ditemukan. .so belum dimuat?", COLOR_ERR)
        return false
    end
    local n = tonumber(f:read("*l"))
    f:close()
    if not n or n == 0 then
        msg("ERROR: alamat tidak valid di addr.txt", COLOR_ERR)
        return false
    end
    api = ffi.cast("ScriptSpyAPI*", n)
    msg("API terhubung. Addr: 0x" .. string.format("%X", n), COLOR_OK)
    return true
end

function main()
    while not isSampAvailable() do wait(100) end
    wait(500)

    -- Coba koneksi ke .so
    if not loadAPI() then
        msg("Gagal load API. Pastikan libscriptspy.so terpasang di AML.", COLOR_ERR)
    end

    -- Command: /spy on|off|status|count|reload
    sampRegisterChatCommand("spy", function(args)
        if not api then
            if args == "reload" then
                loadAPI()
                return
            end
            msg("API belum terhubung. Coba /spy reload", COLOR_ERR)
            return
        end

        if args == "on" then
            api.enable()
            msg("Dumping AKTIF", COLOR_OK)

        elseif args == "off" then
            api.disable()
            msg("Dumping NONAKTIF", COLOR_INFO)

        elseif args == "status" then
            local state = api.is_on() == 1 and "AKTIF" or "NONAKTIF"
            local count = api.count()
            msg(string.format("Status: %s | Total dump: %d", state, count), COLOR_INFO)

        elseif args == "count" then
            msg("Total script ter-dump: " .. api.count(), COLOR_INFO)

        elseif args == "reload" then
            api = nil
            loadAPI()

        else
            msg("Perintah: /spy on | off | status | count | reload", COLOR_INFO)
        end
    end)

    msg("Loaded. Ketik /spy status untuk info.", COLOR_OK)

    while true do wait(2000) end
end
