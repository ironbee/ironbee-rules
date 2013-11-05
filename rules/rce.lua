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

function trim(s)
  return s:gsub("^%s*(.-)%s*$", "%1")
end


function decode_cmd(c)
	local cmd = c

	cmd = string.lower(cmd)

	-- Perform another URL-decoding pass. This is to deal with applications that
	-- perform URL decoding twice. We convert only valid character pairs, because
	-- doing otherwise would open us up for evasion.
	cmd = url_decode(cmd)

	-- TODO Handle %u encoding.

	-- TODO Handle overlong UTF-8.

	-- TODO Handle the half-width/full-width range.

	-- TODO Use best-fit matching as a vulnerable system might, or possibly simply
	--      remove all non-ASCII characters.

	-- TODO Remove Unicode characters that are ignored on OS X.

	-- ATTACK: do not decode HTML entities
	-- the characters & and ; can be abused to confuse the filter
	
	cmd = trim(cmd)

	return cmd
end

function normalize_cmd(c)
	local cmd = c

	cmd = string.gsub(cmd, "^", "")
	cmd = string.gsub(cmd, "\\", "")
	cmd = string.gsub(cmd, ",", "")
	cmd = string.gsub(cmd, "@", "")
	cmd = string.gsub(cmd, "=", "")
	cmd = string.gsub(cmd, "'", "")
	cmd = string.gsub(cmd, "\"", "")
	cmd = string.gsub(cmd, "*", "")
	
	if string.find(cmd, "%$%(([^%)]*)%)") then
		cmd = string.gsub(cmd, "%$%(([^%)]*)%)", ";%1;")
		has_execute_operator = true
	end
		
	-- attack:
	-- the dollar $ is still present and can confuse the filter
	-- ${'(id)'} is transformed to $id
	
	cmd = string.gsub(cmd, "%(", "")
	cmd = string.gsub(cmd, "%)", "")
	cmd = string.gsub(cmd, "{", "")
	cmd = string.gsub(cmd, "}", "")
	
	cmd = string.gsub(cmd, string.char(10), ";")
	cmd = string.gsub(cmd, "\$ifs", " ")
	cmd = string.gsub(cmd, "%s+", " ")
	
	if string.find(cmd, "`") then
		cmd = string.gsub(cmd, "`+", ";")
		has_execute_operator = true
	end
	
	-- attack:
	-- (i`foo`d) will execute "id" but filter sees i;foo;d
	-- thats why we add a score for execution operator detection
	
	cmd = string.gsub(cmd, "|+", ";")
	cmd = string.gsub(cmd, "&+", ";")
	cmd = string.gsub(cmd, ">+", ";")
	cmd = string.gsub(cmd, "<+", ";")
	
	cmd = string.gsub(cmd, "%s*;+%s*", ";")
	
	
	return cmd
end

function is_rce_attack(a)
	local p = 0
	local has_arguments = false
	local has_escape_characters = false
	local has_variables = false
	local has_known_command = false
	has_execute_operator = false;

	if debug then
		print("\nInput: " .. a)
	end

	-- First, convert the input string into something with we can work with.
	
	a = decode_cmd(a)

	if debug then
		print("After decoding: " .. a)
	end
	
	a = normalize_cmd(a)

	if debug then
		print("After normalization: " .. a)
	end

	-- check for escape characters
	
	if string.find(a, ";") then
		has_escape_characters = true
	end
	
	-- detect windows environment variables
	-- http://ss64.com/nt/syntax-variables.html
	
	local variables = file_lines("rce-var-win.data")
	
	for i, v in ipairs(variables) do
		local pattern = "%%" .. escape_lua_metachars(v) .. "%%"

		if string.find(a, pattern) then
			has_variables = true
		end
	end
	
	-- detect linux environment variables

	local variables = file_lines("rce-var-linux.data")

	for i, v in ipairs(variables) do
		local pattern = "%$" .. escape_lua_metachars(v)

		if string.find(a, pattern) then
			has_variables = true
		end
	end


	-- Look for well-known commands

	if has_escape_characters == true then
		local commands = file_lines("rce-commands.data")
		
		for i, v in ipairs(commands) do
			local pattern = "^" .. escape_lua_metachars(v)

			for c in string.gmatch(a, "([^;]+)") do
				if string.find(c, pattern) then
					has_known_command = true
					
					-- look for arguments
					if string.find(c, "%S%s+[-/]") then
						has_arguments = true
						break
					end
				end
			end
			
			if has_arguments then
				break
			end
		end
	end


	if debug then
		print("")
		print("    Has escape char: " .. tostring(has_escape_characters))
		print("    Has execute operator: " .. tostring(has_execute_operator))
		print("    Has variable: " .. tostring(has_variables))
		print("    Has known command: " .. tostring(has_known_command))
		print("    Has arguments: " .. tostring(has_arguments))
	end
	

	-- Decision time.

	if has_escape_characters then
		if has_execute_operator then
			p = 0.5
		else
			p = 0.2
		end
		if has_variables then
			p = p + 0.3
		end
		if has_known_command then
			p = p + 0.5
			if has_arguments then
				p  = p + 0.3
			end
		end
	end

	return p
end

local attacks = file_lines("rce-attacks.data")

for i, v in ipairs(attacks) do
	print(i, v, is_rce_attack(v))

	if debug then
		print("--")
	end
end
