#!/usr/bin/env lua

require "luarocks.loader"
local pcre = require "rex_pcre"

function file_lines(f) 
	local a = {}

	for line in io.lines(f) do
		-- print(line)
		if (line:sub(1,1) ~= '#') then 
			a[#a + 1] = line
		end
	end

	return a
end

function max(a, b)
	if (a > b) then
		return a
	else
		return b
	end
end

-- Path normalization as specified in RFC 3986, section 5.2.4:
--     http://tools.ietf.org/html/rfc3986#section-5.2.4
function remove_dot_segments(s)
	-- This function was copied over from Lua-URI, which is licensed under MIT/X:
	--     http://luaforge.net/projects/uri/

    local path = ""

    while s ~= "" do
        if s:find("^%.%.?/") then -- A
            s = s:gsub("^%.%.?/", "", 1)
        elseif s:find("^/%./") or s == "/." then -- B
            s = s:gsub("^/%./?", "/", 1)
        elseif s:find("^/%.%./") or s == "/.." then -- C
            s = s:gsub("^/%.%./?", "/", 1)
            if path:find("/") then
                path = path:gsub("/[^/]*$", "", 1)
            else
                path = ""
            end
        elseif s == "." or s == ".." then -- D
            s = ""
        else -- E
            local _, p, seg = s:find("^(/?[^/]*)")
            s = s:sub(p + 1)
            path = path .. seg
        end
    end

    return path
end

function decode_path(p)
	local path = p

	path = string.lower(path)

	return path
end

function normalize_path(p)
	local path = p

	-- First, convert all backslashes to forward slashes.
	path = string.gsub(path, "\\", "/")

	-- Then, perform RFC normalization.
	path = remove_dot_segments(path)

	-- Finally, compress consecutive forward slashes.
	path = string.gsub(path, "/+", "/")

	return path
end

function is_lfi_attack(a)
	print("\nInput: " .. a)

	-- First, convert the input string into something with we can work with.
	a = decode_path(a)
	a = normalize_path(a)
	
	print("Normalized: " .. a)

	-- Looking at the string alone, how certain are we that it's a path?

	local p = 0
	
	--[[

	-- TODO There is some value in detecting strings that might be paths.

	-- The beginning looks like an absolute Unix of Windows path?
	if (pcre.match(a, "^([a-z]:)?/")) then
		p = 0.section-5
	end

	-- TODO If the normalized version begins with ./ or ../, it's clearly a path.

	-- The first 128 characters are the same as those typically used in a path?
	if (pcre.match(a, "^[-~:/a-zA-Z0-9._ ]{0,128}")) then
		p = 0.5
	end

	-- Do not proceed if input does not look like a path. This is our attempt to
	-- minimize false positives, although it may be dangerous if someone can convince
	-- us that something does not look a path, even if it is.
	if (p == 0) then
		return 0
	end
	]]--

	-- Look for well-known path fragments; this is a weaker indication of attack,
	-- but may catch those attacks that avoid referencing well-known files.
		
	-- TODO Correlate with: does input look like a path?

	local patterns = file_lines("lfi-fragments.data")
	for i, v in ipairs(patterns) do
		-- TODO Escape meta characters.

		-- Look for the fragment anywhere in the input string.
		if (string.find(a, v)) then
			p = 0.8
		end
	end		

	-- Look for well-known files; this should be a pretty strong indication of attack.

	-- ATTACK POINT We need to maintain a good database of well-known files.

	local filenames = file_lines("lfi-files.data")

	for i, v in ipairs(filenames) do
		-- In order to minimize false positives, we match these full paths from
		-- the beginning of the string only.

		-- ATTACK POINT We rely on our normalization routines to ensure the
		--              beginning of the string does not contain something that
		--              will be ignored when used (e.g., ././././ self-references).

		-- TODO Escape meta characters.
		local pattern = "^" .. v

		if (string.find(a, pattern)) then
			p = 1
		else
			-- Try again, first prepending a forward slash to the input string. We want to
			-- be extra vigilent and match patterns such as "etc/passwd" (our list will
			-- contain it as /etc/passwd).
			-- TODO Change the implementation to avoid having to match twice.
			if (string.find("/" .. a, pattern)) then
				p = 1
			end
		end
	end

	return p
end

local attacks = file_lines("lfi-attacks.data")

for i, v in ipairs(attacks) do
	print(i, v, is_lfi_attack(v))
end