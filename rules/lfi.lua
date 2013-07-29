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

function url_decode(s)
	s = string.gsub(s, "+", " ")
    s = string.gsub(s, "%%(%x%x)", function (h)
        	return string.char(tonumber(h, 16))
       	end)
    return s
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

function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function decode_path(p)
	local path = p

	path = string.lower(path)

	-- Perform another URL-decoding pass. This is to deal with applications that
	-- perform URL decoding twice. We convert only valid character pairs, because
	-- doing otherwise would open us up for evasion.
	path = url_decode(path)

	-- TODO Handle %u encoding.
	-- TODO Handle overlong UTF-8.
	-- TODO Handle the half-width/full-width range.
	-- TODO Use best-fit matching as a vulnerable system might.
	-- TODO Implement other decoding steps vulnerable applications might do. For
	--      example, decode HTML entities.

	-- Strictly speaking, we don't have to trim here because PHP does not ignore
	-- whitespace at the beginning of file names. However, we do because many
	-- applications could be doing the trimming themselves and I suspect the chances
	-- that we'd be introducing false positives are small.
	path = trim(path)

	return path
end

function normalize_path(p)
	local path = p

	-- ATTACK POINT For this type of attack, we assume the attacker is not able to
	--              change IFS to something else.

	-- First, convert all backslashes to forward slashes.
	path = string.gsub(path, "\\", "/")

	-- Useful information about Windows paths: http://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx

	-- If the path starts with "//?/UNC/Server/Share/", remove that part. What
	-- remains should be an absolute path that starts with /.
	-- TODO This is dangerous because we remove potentially large parts of the input.
	local capture = string.match(path, "^/+%?/+unc/.+/.+(/.*)")
	if capture then
	 	path = capture
	end

	-- If the path starts with "//?/c:", remove that part.
	local capture = string.match(path, "^/+%?/+%a:(.+)")
	if capture then
		path = capture
	end

	-- If the path starts with "c:", remove that part. On Unix, a filename that begins
	-- with "c:" is valid, but removing the first two characters won't actually
	-- impact our detection.
	local capture = string.match(path, "^%a:(.+)")
	if capture then
		path = capture
	end

	-- Then, perform RFC normalization to remove the ./ and ../ fragments.
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

	-- Do not allow PHP wrappers.

	if string.match(a, "^php:") then
		return 1
	end

	if string.match(a, "^data:") then
		return 1
	end

	local p = 0
	
	--[[

	-- Entry point: absolute path and relative path. In PHP, relative paths
	-- are evaluated in the context of include_path configuration.

	-- TODO There is some value in detecting strings that might be paths.

	Portable Filename Character Set: [-a-zA-Z0-9_.]
	http://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_276

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

	-- TODO Detect attempt to include PHP session files.

	-- Look for well-known files; this should be a pretty strong indication of attack.

	-- ATTACK POINT Our ability to detect attack (using this approach) depends
	--              on maintaining a good database of well-known files.

	-- ATTACK POINT Could path segment parameters be used for evasion? For
	--              example /etc/passwd written as /etc;p=1/passwd. Not on Mac OSX
	--              10.6.8 or Ubuntu 12.04 LTS, but I wouldn't be surprised if some
	--              platform or filesystem supported it.

	local filenames = file_lines("lfi-files.data")

	for i, v in ipairs(filenames) do
		-- In order to minimize false positives, we match these full paths from
		-- the beginning of the string only.

		-- ATTACK POINT We rely on our normalization routines to ensure the
		--              beginning of the string does not contain something that
		--              will be ignored when used (e.g., ././././ self-references).

		-- ATTACK POINT If PHP's include_path configuration setting is pointing to
		--              a special place (e.g., /etc/), then the attacker might be
		--              able to bypass our well-known filename detection.

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

	-- TODO Look at the string before normalization. Does it look like an LFI attack? For
	--      example, look for the NUL bytes and the truncation attack. Are there too many
	--      self-references? Are self-references mixed with backreferences, etc? Some other
	--      attacks might have an easy to detect (e.g., Windows filename globbing).
	--      Too many backreferences at the beginning might indicate an attempt to reach
	--      the MAX_PATH limit.

	return p
end

local attacks = file_lines("lfi-attacks.data")

for i, v in ipairs(attacks) do
	print(i, v, is_lfi_attack(v))
end