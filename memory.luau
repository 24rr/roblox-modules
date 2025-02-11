
--[[

    Memory Scanner/Editor Module

    Provides low-level memory operations for advanced exploitation

]]



local Memory = {}

local _patternCache = {}

local _memoryRefs = {}



local function hexToBytes(hex)

    return hex:gsub("..", function(x) return string.char(tonumber(x, 16)) end)

end



local function formatAddress(addr)

    return string.format("0x%X", addr and addr or 0)

end



--[[

    Scan memory for byte patterns with optional mask

    Example: Memory.scan("48 89 5C 24 ?? 57 48 83 EC 20", 0x100000, 0x7FFFFFFF)

]]

function Memory.scan(pattern, startAddress, endAddress)

    local bytes, mask = {}, {}

    local chunks = pattern:gsub("%s+", " "):split(" ")

    

    for i, chunk in ipairs(chunks) do

        if chunk == "??" then

            bytes[i] = 0

            mask[i] = "?"

        else

            bytes[i] = tonumber(chunk, 16)

            mask[i] = "x"

        end

    end

    

    local results = {}

    local currentAddr = startAddress or 0x100000

    local maxAddr = endAddress or 0x7FFFFFFF

    

    while currentAddr < maxAddr do

        local success, page = pcall(peek, currentAddr, #bytes)

        if not success then

            currentAddr = currentAddr + 0x1000

        else

            local match = true

            for i = 1, #bytes do

                if mask[i] == "x" and page:byte(i) ~= bytes[i] then

                    match = false

                    break

                end

            end

            if match then

                table.insert(results, currentAddr)

                currentAddr = currentAddr + #bytes

            else

                currentAddr = currentAddr + 1

            end

        end

    end

    

    _patternCache[pattern] = results

    return results

end



--[[

    Create a memory reference that automatically updates when game reloads

]]

function Memory.createDynamicRef(pattern, offset, size)

    local ref = {

        pattern = pattern,

        offset = offset or 0,

        size = size or 4,

        lastKnownAddress = nil,

        valueType = "int"

    }

    

    setmetatable(ref, {

        __index = function(t, k)

            if k == "value" then

                if not t.lastKnownAddress or not pcall(peek, t.lastKnownAddress) then

                    local results = Memory.scan(t.pattern)

                    t.lastKnownAddress = results[1] + t.offset

                end

                return peek(t.lastKnownAddress, t.size)

            end

        end,

        

        __newindex = function(t, k, v)

            if k == "value" and t.lastKnownAddress then

                poke(t.lastKnownAddress, v, t.size)

            end

        end

    })

    

    table.insert(_memoryRefs, ref)

    return ref

end



--[[

    Hook game's memory allocation functions for advanced manipulation

]]

function Memory.hookAllocator()

    local allocHook = hookmetamethod(game, "__namecall", function(...)

        local self, namecallMethod = ...

        if namecallMethod == "Allocate" or namecallMethod == "Reallocate" then

            local size = getnamecallmethod():split(" ")[2]

            print(`Memory operation: {namecallMethod} {size} bytes`)

            -- etc..

        end

        return allocHook(...)

    end)

end
return Memory
