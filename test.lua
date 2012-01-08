#!/usr/bin/env lua

local sha1 = require 'sha1'
local ctx = sha1.new()

assert(getmetatable(ctx) == sha1.SHA1)

for text, sha1 in pairs{
	['abc']
		= 'A9993E364706816ABA3E25717850C26C9CD0D89D',
	['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq']
		= '84983E441C3BD26EBAAE4AA1F95129E5E54670F1',
	['The quick brown fox jumps over the lazy dog']
		= '2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12',
} do
	ctx:add(text)
	local res = ctx:hex()
	print(("'%s'\n   -> %s"):format(text, res))
	assert(res == sha1)
end


for i = 1, 1000000 do
	ctx:add('a')
end

local res = ctx:hex()
print(("A thousand a's\n   -> %s"):format(res))
assert(res == '34AA973CD4C4DAA4F61EEB2BDBAD27316534016F')

-- vim: set ts=2 sw=2 noet:
