local ibmod = ...

local log_event = function(ib, event)
    ib:logError(
        "Handling event=%s: LuaExampleDirective=%s",
        ib.event_name,
        ib.config["LuaExampleDirective"])
    return 0
end

local op = ibmod:operator("rx", "XYZ", 0)

local handler_request = function(ib, event)
    --local args = ib:get("ARGS")
    --for k,f in pairs(args) do
    --    name, val = unpack(f)
    --    ib:logError("ARGS:%s=%s", tostring(name), tostring(val))
    --
    --    local matches = op(f)
    --    if (matches) then
    --        ib:logError("Match")
    --    else
    --        ib:logError("No match")
    --    end
    --end

    local f = ib:getDataField("REQUEST_URI_QUERY")
    ib:logError("REQUEST_URI_QUERY: %s", tostring(f))

    local matches = op(ib, f)
    if (matches) then
        ib:logError("Match")
    else
        ib:logError("No match")
    end

    return 0
end

ibmod:handle_request_event(handler_request)

ibmod:logError("Lua RFI/LFI module loaded.");

return 0
