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

function add_file_lines(t, f)
	local newlines = file_lines(f)

	for i, v in ipairs(newlines) do
		table.insert(t, v)
	end
end

function file_lines(f) 
	local a = {}

	for line in io.lines(f) do
		-- Ignore empty lines and comments
		if ( (line:sub(1,1) ~= '#') and (line:len() ~= 0) ) then 
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


-- Main

local filenames = {}
local fragments = {}

-- Load all complete paths first

add_file_lines(filenames, "lfi-files-panoptic.data")
add_file_lines(filenames, "lfi-files-misc.data")


-- Extract fragments

for i, v in ipairs(filenames) do
	-- print("Filename: " .. v)

	-- Now break the filename into individual fragments.
	local previous = nil
	for token in string.gmatch(v, "[^/]+") do
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
		fragments[previous] = true
		-- print("Last: " .. previous)
	end
end

table.sort(filenames)
write_array_to_file(filenames, "lfi-files.data")

local sorted_fragments = {}
for i, v in pairs(fragments) do
	table.insert(sorted_fragments, i)
end

table.sort(sorted_fragments)
write_array_to_file(sorted_fragments, "lfi-fragments.data")

print("Found " .. #filenames .. " filename patterns and " .. table_size(fragments) .. " fragments.")
