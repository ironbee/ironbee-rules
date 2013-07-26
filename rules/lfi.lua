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

function is_lfi_attack(a)
	a = string.lower(a)
	
	-- Looking at the string alone, how certain are we that it's a path?

	local p = 0
	
	-- The beginning looks like an absolute Unix of Windows path?
	if (pcre.match(a, "^([a-z]:)?/")) then
		p = 0.5
	end

	-- TODO If the normalized version begins with ./ or ../, it's clearly a path.

	-- The first 128 characters are the same as those typically used in a path?
	if (pcre.match(a, "^[-~:/a-zA-Z0-9._ ]{0,128}")) then
		p = 0.5
	end

	-- If we believe the value is a path, then also look for common
	-- patterns. This is our attempt to minimize false positives, although
	-- it may be dangerous if someone can convince us that something does
	-- not look a path, even if it is.
	if (p > 0) then
		-- Look for well-known path fragments; this is a weaker indication of
		-- attack, but may catch those attacks that avoid referencing well-known files.
		
		local patterns = file_lines("lfi-fragments.data")
		for i, v in ipairs(patterns) do
			-- Look for the fragment anywhere in the input string.
			if (string.find(a, v)) then
				p = 0.8
			end
		end		

		-- Look for well-known files; this should be a pretty strong indication of attack.

		local patterns = file_lines("lfi-files.data")

		for i, v in ipairs(patterns) do
			-- TODO Look at the beginning of input only, but ignoring /../ and ../ fragments. We're
			--      assuming we can counter evasion. Of course, the mere presence of backreferences
			--      and similar evasion methods is highly suspicious.
			if (string.find(a, v)) then
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