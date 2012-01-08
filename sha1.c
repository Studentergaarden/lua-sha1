/*
 * SHA-1 in C
 * by Emil Renner Berthing <esmil@mailme.dk>
 *
 * Based on code in public domain by
 * Steve Reid <sreid@sea-to-sky.net>
 *
 * Still 100% Public Domain
 */

#include <string.h>
#include <inttypes.h>
#include <lua.h>
#include <lauxlib.h>

#define SHA1_DIGEST_LENGTH 20
#define SHA1_BLOCKSIZE 64

struct sha1_context {
    uint32_t state[5];
    uint64_t length;
    char     buf[SHA1_BLOCKSIZE];
};

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
#define blk0(i) (block[i] = \
	(block[i]>>24) | ((block[i]<<8) & 0x00FF0000) | \
	((block[i]>>8) & 0x0000FF00) | (block[i]<<24))
#define blk(i) (block[i & 15] = rol( \
	block[(i -  3) & 15] ^ block[(i - 8) & 15] ^ \
	block[(i - 14) & 15] ^ block[i & 15], 1))

/* transform one 512bit block. this is the core of the algorithm. */
static void
sha1_transform(uint32_t state[5], char buf[SHA1_BLOCKSIZE])
{
	uint32_t a, b, c, d, e;
	uint32_t *block = (uint32_t *)buf;
#ifdef SHA1_SHORTCODE
	unsigned int i;
#endif

	/* copy state to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

#ifdef SHA1_SHORTCODE
	for (i = 0; i < 80; i++) {
		uint32_t t;

		if (i < 20)
			t = ((b & (c ^ d)) ^ d)       + 0x5A827999;
		else if (i < 40)
			t = (b ^ c ^ d)               + 0x6ED9EBA1;
		else if (i < 60)
			t = (((b | c) & d) | (b & c)) + 0x8F1BBCDC;
		else
			t = (b ^ c ^ d)               + 0xCA62C1D6;

		t += (i < 16) ? blk0(i) : blk(i);
		t += e + rol(a, 5);

		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = t;
	}
#else

/* R0 and R1, R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) \
	z += ((w&(x^y))^y)     + blk0(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30)
#define R1(v,w,x,y,z,i) \
	z += ((w&(x^y))^y)     + blk(i)  + 0x5A827999 + rol(v, 5); w = rol(w, 30)
#define R2(v,w,x,y,z,i) \
	z += (w^x^y)           + blk(i)  + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30)
#define R3(v,w,x,y,z,i) \
	z += (((w|x)&y)|(w&x)) + blk(i)  + 0x8F1BBCDC + rol(v, 5); w = rol(w, 30)
#define R4(v,w,x,y,z,i) \
	z += (w^x^y)           + blk(i)  + 0xCA62C1D6 + rol(v, 5); w = rol(w, 30)

	/* 4 rounds of 20 operations each. loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
#endif

	/* add the working vars back into state */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

/* initialize new context */
static void
sha1_init(struct sha1_context *ctx)
{
	/* SHA1 initialization constants */
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->length = 0;
}

/* hash more data */
static void
sha1_update(struct sha1_context *ctx, const char *data, size_t len)
{
	unsigned int offset = ctx->length & (SHA1_BLOCKSIZE - 1);

	ctx->length += len;

	if (offset + len >= SHA1_BLOCKSIZE) {
		unsigned int n = SHA1_BLOCKSIZE - offset;

		memcpy(ctx->buf + offset, data, n);
		sha1_transform(ctx->state, ctx->buf);
		data += n;
		len -= n;

		while (len >= SHA1_BLOCKSIZE) {
			memcpy(ctx->buf, data, SHA1_BLOCKSIZE);
			sha1_transform(ctx->state, ctx->buf);
			data += SHA1_BLOCKSIZE;
			len -= SHA1_BLOCKSIZE;
		}

		memcpy(ctx->buf, data, len);
	} else
		memcpy(ctx->buf + offset, data, len);
}

/* end hashing and return the final hash */
static void
sha1_final(struct sha1_context *ctx, char out[SHA1_DIGEST_LENGTH])
{
	unsigned int offset = ctx->length & (SHA1_BLOCKSIZE - 1);
	unsigned int i;

	/* append the '1' bit */
	ctx->buf[offset++] = (char)0x80;

	/* if there are less than 8 bytes of the buffer free
	 * for the bitsize, append zeros and transform */
	if (offset > SHA1_BLOCKSIZE - 8) {
		while (offset < SHA1_BLOCKSIZE)
			ctx->buf[offset++] = 0;
		sha1_transform(ctx->state, ctx->buf);
		offset = 0;
	}

	/* pad with zeroes until we add the bitsize */
	while (offset < SHA1_BLOCKSIZE - sizeof(ctx->length))
		ctx->buf[offset++] = 0;

	/* store bitsize big-endian and do the final transform */
	ctx->buf[offset++] = (ctx->length >> 53) & 0xff;
	ctx->buf[offset++] = (ctx->length >> 45) & 0xff;
	ctx->buf[offset++] = (ctx->length >> 37) & 0xff;
	ctx->buf[offset++] = (ctx->length >> 29) & 0xff;
	ctx->buf[offset++] = (ctx->length >> 21) & 0xff;
	ctx->buf[offset++] = (ctx->length >> 13) & 0xff;
	ctx->buf[offset++] = (ctx->length >>  5) & 0xff;
	ctx->buf[offset++] = (ctx->length <<  3) & 0xff;
	sha1_transform(ctx->state, ctx->buf);

	/* copy output */
	for (i = 0; i < 5; i++) {
		*out++ = (ctx->state[i] >> 24) & 0xff;
		*out++ = (ctx->state[i] >> 16) & 0xff;
		*out++ = (ctx->state[i] >>  8) & 0xff;
		*out++ =  ctx->state[i]        & 0xff;
	}
}

static int
sha1_add(lua_State *L)
{
	struct sha1_context *ctx;
	const char *data;
	size_t len;

	luaL_checktype(L, 1, LUA_TUSERDATA);
	data = luaL_checklstring(L, 2, &len);

	ctx = lua_touserdata(L, 1);

	sha1_update(ctx, data, len);

	/* return self to allow chaining */
	lua_settop(L, 1);
	return 1;
}

static int
sha1_raw(lua_State *L)
{
	struct sha1_context *ctx;
	char out[SHA1_DIGEST_LENGTH];

	luaL_checktype(L, 1, LUA_TUSERDATA);
	ctx = lua_touserdata(L, 1);

	sha1_final(ctx, out);
	sha1_init(ctx);

	lua_pushlstring(L, out, SHA1_DIGEST_LENGTH);
	return 1;
}

static const char hex_digit[] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static int
sha1_hex(lua_State *L)
{
	struct sha1_context *ctx;
	char out[2*SHA1_DIGEST_LENGTH];
	unsigned int i;
	char *p;
	char *q;

	luaL_checktype(L, 1, LUA_TUSERDATA);
	ctx = lua_touserdata(L, 1);
	p = out + SHA1_DIGEST_LENGTH;
	q = out;

	sha1_final(ctx, p);
	sha1_init(ctx);

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		unsigned char ch = *p++;

		*q++ = hex_digit[ch >> 4];
		*q++ = hex_digit[ch & 0x0F];
	}

	lua_pushlstring(L, out, 2*SHA1_DIGEST_LENGTH);
	return 1;
}

static int
sha1_new(lua_State *L)
{
	struct sha1_context *ctx;

	ctx = lua_newuserdata(L, sizeof(struct sha1_context));
	sha1_init(ctx);

	/* set metatable */
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_setmetatable(L, -2);

	return 1;
}

int
luaopen_sha1(lua_State *L)
{
	lua_createtable(L, 0, 2);

	/* create metatable */
	lua_createtable(L, 0, 4);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	/* insert add method */
	lua_pushcfunction(L, sha1_add);
	lua_setfield(L, -2, "add");

	/* insert raw method */
	lua_pushcfunction(L, sha1_raw);
	lua_setfield(L, -2, "raw");

	/* insert hex method */
	lua_pushcfunction(L, sha1_hex);
	lua_setfield(L, -2, "hex");

	/* insert new function */
	lua_pushvalue(L, -1); /* upvalue 1: metatable */
	lua_pushcclosure(L, sha1_new, 1);
	lua_setfield(L, -3, "new");

	/* insert metatable */
	lua_setfield(L, -2, "SHA1");

	return 1;
}
