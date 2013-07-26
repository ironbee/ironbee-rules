#!/usr/bin/env lua

require "luarocks.loader"
local pcre = require "rex_pcre"

function table_size(t)
	local c = 0

	for i, v in pairs(t) do
		c = c + 1
	end

	return c
end

function file_lines(f) 
	local a = {}

	for line in io.lines(f) do
		-- Ignore comments
		if (line:sub(1, 1) ~= '#') then 
			table.insert(a, line)
		end
	end

	return a
end

function write_array_to_file(a, filename)
	local f = assert(io.open(filename, "w"))
	
	for i, v in ipairs(a) do
		f:write(v .. "\n")
	end

	f:close()
end

function write_table_keys_to_file(t, filename)
	local f = assert(io.open(filename, "w"))

	for i, v in pairs(t) do
		f:write(i .. "\n")
	end

	f:close()
end

local lines = file_lines("cases.xml")

local filenames = {}
local fragments = {}

r = pcre.new("<file value=\"(.+)\"")

for i, v in ipairs(lines) do
	-- print("Line: " .. v)

	local name = r:match(v)
	if name then
		name = name:lower()

		-- Ignore if the string contains a macro, e.g., {HOST}.
		if string.match(name, "{") then
			goto continue
		end

		table.insert(filenames, name)

		-- Now break the filename into individual fragments.
		local previous = nil
		for token in string.gmatch(name, "[^/]+") do
   			if previous then
   				fragments["/" .. previous .. "/"] = true
   				-- print("Token: " .. previous)
   			end

   			previous = token

   			-- Ignore if the token is a number (e.g., from /proc/self/fd/0).
   			if string.match(previous, "^%d+$") then
   				previous = nil
   			end
		end

		if previous then
			fragments["/" .. previous] = true
			-- print("Last: " .. previous)
		end

		::continue::
	end
end

write_array_to_file(filenames, "lfi-files.data")
write_table_keys_to_file(fragments, "lfi-fragments.data")

print("Found " .. #filenames .. " filename patterns and " .. table_size(fragments) .. " fragments.")
