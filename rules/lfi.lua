#!/usr/bin/env lua

require "luarocks.loader"
local pcre = require "rex_pcre"

local debug = true

function max(v1, v2)
	if v1 > v2 then
		return v1
	else
		return v2
	end
end

function count_matches(haystack, needle)
	local count = 0
	local i = 0
	
	while true do
		i = string.find(haystack, needle, i + 1)
		if i == nil then break end
		count = count + 1
	end

	return count
end

function count_matches_len(haystack, needle)
	local len = 0
    for w in string.gmatch(haystack, "(" .. needle .. ")") do
      len = len + #w
    end
	return len
end

function file_lines(f) 
	local a = {}

	for line in io.lines(f) do
		line = trim(line)

		-- Ignore empty lines and comments
		if (line:sub(1,1) ~= '#') and (line:len() ~= 0) then 
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

function escape_lua_metachars(s)
	return(s:gsub("[-().%%+*?[%]^$]", function (chr) return "%" .. chr end))
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
  return s:gsub("^%s*(.-)%s*$", "%1")
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

	-- TODO Use best-fit matching as a vulnerable system might, or possibly simply
	--      remove all non-ASCII characters.

	-- TODO Remove Unicode characters that are ignored on OS X.

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

	-- ATTACK POINT For this type of attack, we assume the attacker is not able to change the
	--              shell IFS (Internal Field Separator). This is unlikely for LFI, as these
	--              attacks are not carried out via a shell.

	-- First, convert all backslashes to forward slashes.
	path = string.gsub(path, "\\", "/")

	-- ATTACK POINT Normalization done here will fail if the target system allows for other characters
	--              as path segment separators. An old example: http://seclists.org/bugtraq/2000/Oct/264

	-- If the path starts with "//?/", remove it.
	local capture = string.match(path, "^/+%?/+(.+)")
	if capture then
		path = capture
	end

	-- If the path starts with "//./", remove it.
	local capture = string.match(path, "^/+%./+(.+)")
	if capture then
		path = capture
	end

	-- If the path starts with "c:", remove that part. On Unix, a filename that begins
	-- with "c:" is valid, but removing the first two characters hopefully shouldn't impact our detection.
	local capture = string.match(path, "^%a:(.+)")
	if capture then
		path = capture
	end

	return path
end

function is_lfi_attack(a)
	local p = 0
	local looks_like_a_path = false
	local contains_wildcards = false
	local have_full_match = false
	local have_fragment_match = false
	local has_terminator = false
	local upload_tmp_attack = false
	local seen_wrapper = false
	local path_fluff_len = 0
	local consecutive_slashes = 0
	local self_references = 0
	local back_references = 0
	local multiple_dots_len = 0

	if debug then
		print("\nInput: " .. a)
	end

	-- First, convert the input string into something with we can work with.
	
	a = decode_path(a)

	if debug then
		print("After decoding: " .. a)
	end
	
	a = normalize_path(a)

	if debug then
		print("After normalization: " .. a)
	end

	-- Count ./ fragments before we remove them.

	local self_references = count_matches(a, "/%./")
	if string.match(a, "^%./") then
		self_references = self_references + 1
	end

	-- Count ../ fragments before we remove them.

	local back_references = count_matches(a, "/%.%./")
	if string.match(a, "^%.%./") then
		back_references = back_references + 1
	end

	-- Count consecutive slashes before we reduce them.
	consecutive_slashes = count_matches_len(a, "//+")

	-- Count the lenght of groups of 3 dots and more.
	multiple_dots_len = count_matches_len(a, "%.%.%.+")


	local path_fluff_len = #a

	-- Remove ./ and ../ dot segments.
	a = remove_dot_segments(a)

	-- Compress consecutive forward slashes.
	a = string.gsub(a, "/+", "/")

	if debug then
		print("After dot segment removal: " .. a)
	end

	path_fluff_len = path_fluff_len - #a


	-- PHP wrappers (http://php.net/manual/en/wrappers.data.php)
	--
	-- Most wrappers require the presence of the "://" sequence after the scheme name, but
	-- the "data:" wrapper does not (RFC 2397, http://tools.ietf.org/html/rfc2397).
	-- beware: after normalization php://input becomes php:/input
	
	-- added for JSP: jar:, jndi:, url:
	-- url: can be used for filter evasion, for example: url:file:///

	-- NOTE We do not detect http, https, and ftp schemes as wrappers. We focus
	--      on LFI here, and those fall under RFI.
		
	local wrappers = file_lines("rfi-wrapper.data")
	
	for i, v in ipairs(wrappers) do
		local pattern = "^" .. escape_lua_metachars(v) .. ":"

		if string.find(a, pattern) then
			seen_wrapper = true
		end
	end
	
		
	-- Detect attempts to include PHP session files (e.g., /tmp/sess_SESSIONID). To
	-- do this, we have common session storage locations on the known files list. The
	-- paths are usually /tmp/, /var/lib/php5/ (Debian, Ubuntu), and /var/lib/php/session
	-- (Red Hat). The format of each session file is sess_SESSIONID.


	-- Look for well-known files; this should be a pretty strong indication of attack.
	-- Our list includes files that might contain information useful to the attacker,
	-- as well as files that the attacker might write to indirectly (e.g., web server
	-- logs, uploaded files, PHP session storage, environment, etc). The latter are
	-- typically used to escalate LFI to RCE.

	-- ATTACK POINT Our ability to detect attacks (using this approach) depends
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
		--              able to bypass our well-known filename detection. Same with
		--              other platforms that may have other interesting points of entry.

		local pattern = "^" .. escape_lua_metachars(v)

		if string.find(a, pattern) then
			have_full_match = true
			
			if debug then
				print("Matched: " .. pattern)
			end
		else
			-- Try again, first prepending a forward slash to the input string. We want to
			-- be extra vigilent and match patterns such as "etc/passwd" (our list will
			-- contain it as /etc/passwd).

			if (string.find("/" .. a, pattern)) then
				have_full_match = true

				if debug then
					print("Matched: " .. pattern)
				end
			end
		end
	end


	-- Look for well-known path fragments; this is a weaker indication of attack,
	-- but may catch those attacks that avoid referencing well-known files.

	if have_full_match == false then
		local patterns = file_lines("lfi-fragments.data")

		for i, v in ipairs(patterns) do
			local pattern = escape_lua_metachars(v)

			-- Look for the fragment anywhere in the input string.
			if (string.find(a, pattern)) then
				have_fragment_match = true
				
			else
				-- Try again, first prepending a forward slash to the input string. We want to
				-- be extra vigilent and match patterns such as "etc/passwd" (our list will
				-- contain it as /etc/passwd).

				if (string.find("/" .. a, pattern)) then
					have_fragment_match = true
				end
			end
		end
	end


	-- The first 128 characters are the same as those typically used in a path?
	
	-- Portable Filename Character Set: [-a-zA-Z0-9_.]
	-- http://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_276

	if (pcre.match(a, "^[-\"<>~:/a-zA-Z0-9._ ]{0,128}")) then
		-- To minimize false positives, require at least one
		-- forward slash to decide the input looks like a path.
		if (string.find(a, "/")) then
			looks_like_a_path = true
		
			-- wildcards work only on windows
			-- wildcards does not work in JSP/Tomcat
			if (string.find(a, "[<>]")) then
				contains_wildcards = true
			end
		end

		-- TODO Input that begins with a drive letter (e.g., c:), dot, and slash
		--      is more likely to be a path.

		-- TODO Path detection should be better (smarter).
	end


	-- Many of the following techniques are obsolete, but we can expect to continue to see
	-- them because 1) unpatched systems remain, 2) tools continue to have them, and 3) the
	-- attackers will try anything.


	-- NUL byte attack against PHP (CVE-2006-7243). Fixed in PHP 5.3.4.
	--     http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7243
	--     https://bugs.php.net/bug.php?id=39863

	-- In JSP, the character ; or ? terminates a path within 
	-- <jsp:include page="<%= file %>" /> and
	-- <c:import url="<%= file %>" />
	
	-- Terminators should probably not be allowed, but we'll leave other rules
	-- to take care of that. We'll only detect.
	if (string.find(a, string.char(0)) or string.find(a, ';') or string.find(a, '?')) then
		has_terminator = true
	end


	-- PHP LFI to arbitrary code execution via rfc1867 file upload temporary files

	if looks_like_a_path then
		-- Examples:
		--   c:/windows/temp/php<<
		--   c:/windows/temp/php12<<
    	--   c:/windows/temp/php>>>>.tmp
        --   c:/windows/temp/php<<%00garbage
        --   c:/windows/temp/php>>>>
		if (pcre.match(a, "php[a-f0-9><]+(?:\\.tmp)?(?:\\x00.*)?$")) then
			upload_tmp_attack = true
		end

		-- Examples:
		--   /tmp/php67DedX
		--   /tmp/php67DedX%00garbage
		if (pcre.match(a, "php[a-z0-9]+(?:\\x00.*)?$")) then
			upload_tmp_attack = true
		end
	end

	if debug then
		print("")
		print("    Have full match: " .. tostring(have_full_match))
		print("    Have fragment match: " .. tostring(have_fragment_match))
		print("    Looks like a path: " .. tostring(looks_like_a_path))
		print("    Has terminator: " .. tostring(has_terminator))
		print("    Self-references: " .. self_references)
		print("    Back-references: " .. back_references)
		print("    Consecutive slashes: " .. consecutive_slashes)
		print("    Upload temporary file attack: " .. tostring(upload_tmp_attack))
		print("    Path fluff length: " .. path_fluff_len)
		print("    Multiple dots length: " .. multiple_dots_len)
		print("    Contains wildcards: " .. tostring(contains_wildcards))
		print("    Contains wrapper: " .. tostring(seen_wrapper))
	end

	-- Decision time.

	if have_full_match then
		p = 1
	else
		if looks_like_a_path then
			p = 0.2

			if have_fragment_match then
				p = 0.5
			end

			-- TODO Need better handling of wildcards. Perhaps try to match one
			--      of the known Windows files?

			if contains_wildcards then
				p = 0.5
			end
		end

		if upload_tmp_attack then
			p = p + 0.6
		end
	end

	if seen_wrapper then
		p = max(p, 1)
	end

	-- TODO In order to simplify the calculation and make it more predictable,
	--      replace the calculation below with a single capped single evasion score.
	--      With the current system we risk counting the same sequence(s) more than
	--      once.

	if has_terminator then
		p = p + 0.1
	end

	if self_references > 0 then
		p = p + 0.1
	end

	if self_references > 1 then
		p = p + 0.3
	end

	if back_references > 0 then
		p = p + 0.1
	end

	if consecutive_slashes > 2 then
		p = p + 0.1
	end

	if path_fluff_len > 10 then
		p = p + 0.5
	end

	return p
end

local attacks = file_lines("lfi-attacks.data")

for i, v in ipairs(attacks) do
	print(i, v, is_lfi_attack(v))

	if debug then
		print("--")
	end
end
