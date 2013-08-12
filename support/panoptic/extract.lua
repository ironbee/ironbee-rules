#!/usr/bin/env lua

require "luarocks.loader"
local pcre = require "rex_pcre"

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

local lines = file_lines("cases.xml")

local filenames = {}

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

		::continue::
	end
end

table.sort(filenames)
write_array_to_file(filenames, "lfi-files-panoptic.data")

print("Found " .. #filenames .. " filename patterns.")
