/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/* Implementation of LTC_RIPEMD-128 based on the source by Antoon Bosselaers, ESAT-COSIC
 *
 * This source has been radically overhauled to be portable and work within
 * the LibTomCrypt API by Tom St Denis
 */

#include "ripemd128.h"
#include <memory.h>
#include <stdlib.h>

#ifndef MAX
   #define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
   #define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

/* the four basic functions F(), G() and H() */
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 

#if defined __linux__
// Add by Zhang Luduo, 2019-12
	#define _lrotr(value, shift)\
		((value >> shift) + (value << (32 - shift)))
	#define _lrotl(value, shift)\
		((value << shift) + (value >> (32 - shift)))
#endif

#define ROR(x,n) _lrotr(x,n)
#define ROL(x,n) _lrotl(x,n)
#define RORc(x,n) _lrotr(x,n)
#define ROLc(x,n) _lrotl(x,n)
  
/* the eight basic operations FF() through III() */
#define FF(a, b, c, d, x, s)        \
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROLc((a), (s));

#define GG(a, b, c, d, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROLc((a), (s));

#define HH(a, b, c, d, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROLc((a), (s));

#define II(a, b, c, d, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROLc((a), (s));

#define FFF(a, b, c, d, x, s)        \
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROLc((a), (s));

#define GGG(a, b, c, d, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROLc((a), (s));

#define HHH(a, b, c, d, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROLc((a), (s));

#define III(a, b, c, d, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROLc((a), (s));

#define XMEMCPY  memcpy

#define LOAD32L(x, y)         \
     XMEMCPY(&(x), y, 4);

#define STORE32L(x, y)        \
     { ulong32  __t = (x); XMEMCPY(y, &__t, 4); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

static int ripemd128_compress(ripemd128_context* ctx, unsigned char *buf)
{
   ulong32 aa,bb,cc,dd,aaa,bbb,ccc,ddd,X[16];
   int i;
   
   /* load words X */
   for (i = 0; i < 16; i++){
      LOAD32L(X[i], buf + (4 * i));
   }

   /* load state */
   aa = aaa = ctx->state[0];
   bb = bbb = ctx->state[1];
   cc = ccc = ctx->state[2];
   dd = ddd = ctx->state[3];

   /* round 1 */
   FF(aa, bb, cc, dd, X[ 0], 11);
   FF(dd, aa, bb, cc, X[ 1], 14);
   FF(cc, dd, aa, bb, X[ 2], 15);
   FF(bb, cc, dd, aa, X[ 3], 12);
   FF(aa, bb, cc, dd, X[ 4],  5);
   FF(dd, aa, bb, cc, X[ 5],  8);
   FF(cc, dd, aa, bb, X[ 6],  7);
   FF(bb, cc, dd, aa, X[ 7],  9);
   FF(aa, bb, cc, dd, X[ 8], 11);
   FF(dd, aa, bb, cc, X[ 9], 13);
   FF(cc, dd, aa, bb, X[10], 14);
   FF(bb, cc, dd, aa, X[11], 15);
   FF(aa, bb, cc, dd, X[12],  6);
   FF(dd, aa, bb, cc, X[13],  7);
   FF(cc, dd, aa, bb, X[14],  9);
   FF(bb, cc, dd, aa, X[15],  8);
                             
   /* round 2 */
   GG(aa, bb, cc, dd, X[ 7],  7);
   GG(dd, aa, bb, cc, X[ 4],  6);
   GG(cc, dd, aa, bb, X[13],  8);
   GG(bb, cc, dd, aa, X[ 1], 13);
   GG(aa, bb, cc, dd, X[10], 11);
   GG(dd, aa, bb, cc, X[ 6],  9);
   GG(cc, dd, aa, bb, X[15],  7);
   GG(bb, cc, dd, aa, X[ 3], 15);
   GG(aa, bb, cc, dd, X[12],  7);
   GG(dd, aa, bb, cc, X[ 0], 12);
   GG(cc, dd, aa, bb, X[ 9], 15);
   GG(bb, cc, dd, aa, X[ 5],  9);
   GG(aa, bb, cc, dd, X[ 2], 11);
   GG(dd, aa, bb, cc, X[14],  7);
   GG(cc, dd, aa, bb, X[11], 13);
   GG(bb, cc, dd, aa, X[ 8], 12);

   /* round 3 */
   HH(aa, bb, cc, dd, X[ 3], 11);
   HH(dd, aa, bb, cc, X[10], 13);
   HH(cc, dd, aa, bb, X[14],  6);
   HH(bb, cc, dd, aa, X[ 4],  7);
   HH(aa, bb, cc, dd, X[ 9], 14);
   HH(dd, aa, bb, cc, X[15],  9);
   HH(cc, dd, aa, bb, X[ 8], 13);
   HH(bb, cc, dd, aa, X[ 1], 15);
   HH(aa, bb, cc, dd, X[ 2], 14);
   HH(dd, aa, bb, cc, X[ 7],  8);
   HH(cc, dd, aa, bb, X[ 0], 13);
   HH(bb, cc, dd, aa, X[ 6],  6);
   HH(aa, bb, cc, dd, X[13],  5);
   HH(dd, aa, bb, cc, X[11], 12);
   HH(cc, dd, aa, bb, X[ 5],  7);
   HH(bb, cc, dd, aa, X[12],  5);

   /* round 4 */
   II(aa, bb, cc, dd, X[ 1], 11);
   II(dd, aa, bb, cc, X[ 9], 12);
   II(cc, dd, aa, bb, X[11], 14);
   II(bb, cc, dd, aa, X[10], 15);
   II(aa, bb, cc, dd, X[ 0], 14);
   II(dd, aa, bb, cc, X[ 8], 15);
   II(cc, dd, aa, bb, X[12],  9);
   II(bb, cc, dd, aa, X[ 4],  8);
   II(aa, bb, cc, dd, X[13],  9);
   II(dd, aa, bb, cc, X[ 3], 14);
   II(cc, dd, aa, bb, X[ 7],  5);
   II(bb, cc, dd, aa, X[15],  6);
   II(aa, bb, cc, dd, X[14],  8);
   II(dd, aa, bb, cc, X[ 5],  6);
   II(cc, dd, aa, bb, X[ 6],  5);
   II(bb, cc, dd, aa, X[ 2], 12);

   /* parallel round 1 */
   III(aaa, bbb, ccc, ddd, X[ 5],  8); 
   III(ddd, aaa, bbb, ccc, X[14],  9);
   III(ccc, ddd, aaa, bbb, X[ 7],  9);
   III(bbb, ccc, ddd, aaa, X[ 0], 11);
   III(aaa, bbb, ccc, ddd, X[ 9], 13);
   III(ddd, aaa, bbb, ccc, X[ 2], 15);
   III(ccc, ddd, aaa, bbb, X[11], 15);
   III(bbb, ccc, ddd, aaa, X[ 4],  5);
   III(aaa, bbb, ccc, ddd, X[13],  7);
   III(ddd, aaa, bbb, ccc, X[ 6],  7);
   III(ccc, ddd, aaa, bbb, X[15],  8);
   III(bbb, ccc, ddd, aaa, X[ 8], 11);
   III(aaa, bbb, ccc, ddd, X[ 1], 14);
   III(ddd, aaa, bbb, ccc, X[10], 14);
   III(ccc, ddd, aaa, bbb, X[ 3], 12);
   III(bbb, ccc, ddd, aaa, X[12],  6);

   /* parallel round 2 */
   HHH(aaa, bbb, ccc, ddd, X[ 6],  9);
   HHH(ddd, aaa, bbb, ccc, X[11], 13);
   HHH(ccc, ddd, aaa, bbb, X[ 3], 15);
   HHH(bbb, ccc, ddd, aaa, X[ 7],  7);
   HHH(aaa, bbb, ccc, ddd, X[ 0], 12);
   HHH(ddd, aaa, bbb, ccc, X[13],  8);
   HHH(ccc, ddd, aaa, bbb, X[ 5],  9);
   HHH(bbb, ccc, ddd, aaa, X[10], 11);
   HHH(aaa, bbb, ccc, ddd, X[14],  7);
   HHH(ddd, aaa, bbb, ccc, X[15],  7);
   HHH(ccc, ddd, aaa, bbb, X[ 8], 12);
   HHH(bbb, ccc, ddd, aaa, X[12],  7);
   HHH(aaa, bbb, ccc, ddd, X[ 4],  6);
   HHH(ddd, aaa, bbb, ccc, X[ 9], 15);
   HHH(ccc, ddd, aaa, bbb, X[ 1], 13);
   HHH(bbb, ccc, ddd, aaa, X[ 2], 11);

   /* parallel round 3 */   
   GGG(aaa, bbb, ccc, ddd, X[15],  9);
   GGG(ddd, aaa, bbb, ccc, X[ 5],  7);
   GGG(ccc, ddd, aaa, bbb, X[ 1], 15);
   GGG(bbb, ccc, ddd, aaa, X[ 3], 11);
   GGG(aaa, bbb, ccc, ddd, X[ 7],  8);
   GGG(ddd, aaa, bbb, ccc, X[14],  6);
   GGG(ccc, ddd, aaa, bbb, X[ 6],  6);
   GGG(bbb, ccc, ddd, aaa, X[ 9], 14);
   GGG(aaa, bbb, ccc, ddd, X[11], 12);
   GGG(ddd, aaa, bbb, ccc, X[ 8], 13);
   GGG(ccc, ddd, aaa, bbb, X[12],  5);
   GGG(bbb, ccc, ddd, aaa, X[ 2], 14);
   GGG(aaa, bbb, ccc, ddd, X[10], 13);
   GGG(ddd, aaa, bbb, ccc, X[ 0], 13);
   GGG(ccc, ddd, aaa, bbb, X[ 4],  7);
   GGG(bbb, ccc, ddd, aaa, X[13],  5);

   /* parallel round 4 */
   FFF(aaa, bbb, ccc, ddd, X[ 8], 15);
   FFF(ddd, aaa, bbb, ccc, X[ 6],  5);
   FFF(ccc, ddd, aaa, bbb, X[ 4],  8);
   FFF(bbb, ccc, ddd, aaa, X[ 1], 11);
   FFF(aaa, bbb, ccc, ddd, X[ 3], 14);
   FFF(ddd, aaa, bbb, ccc, X[11], 14);
   FFF(ccc, ddd, aaa, bbb, X[15],  6);
   FFF(bbb, ccc, ddd, aaa, X[ 0], 14);
   FFF(aaa, bbb, ccc, ddd, X[ 5],  6);
   FFF(ddd, aaa, bbb, ccc, X[12],  9);
   FFF(ccc, ddd, aaa, bbb, X[ 2], 12);
   FFF(bbb, ccc, ddd, aaa, X[13],  9);
   FFF(aaa, bbb, ccc, ddd, X[ 9], 12);
   FFF(ddd, aaa, bbb, ccc, X[ 7],  5);
   FFF(ccc, ddd, aaa, bbb, X[10], 15);
   FFF(bbb, ccc, ddd, aaa, X[14],  8);

   /* combine results */
   ddd += cc + ctx->state[1];               /* final result for MDbuf[0] */
   ctx->state[1] = ctx->state[2] + dd + aaa;
   ctx->state[2] = ctx->state[3] + aa + bbb;
   ctx->state[3] = ctx->state[0] + bb + ccc;
   ctx->state[0] = ddd;

   return CRYPT_OK;
}

/**
   Initialize the hash state
   @param ctx   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int ripemd128_init(ripemd128_context* ctx)
{
   ctx->state[0] = 0x67452301UL;
   ctx->state[1] = 0xefcdab89UL;
   ctx->state[2] = 0x98badcfeUL;
   ctx->state[3] = 0x10325476UL;
   ctx->curlen   = 0;
   ctx->length   = 0;

   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param ctx     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int ripemd128_process (ripemd128_context* ctx, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;

    if (ctx->curlen > sizeof(ctx->buf)) {
       return CRYPT_INVALID_ARG;
    }
    while (inlen > 0) {
        if (ctx->curlen == 0 && inlen >= _RMD128_BLOCK_SIZE) {
           if ((err = ripemd128_compress (ctx, (unsigned char *)in)) != CRYPT_OK) {
              return err;
           }
           ctx->length += _RMD128_BLOCK_SIZE * 8;
           in             += _RMD128_BLOCK_SIZE;
           inlen          -= _RMD128_BLOCK_SIZE;
        } else {
           n = MIN(inlen, (_RMD128_BLOCK_SIZE - ctx->curlen));
           memcpy(ctx->buf + ctx->curlen, in, (size_t)n);
           ctx->curlen += n;
           in += n;
           inlen -= n;
           if (ctx->curlen == _RMD128_BLOCK_SIZE) {
              if ((err = ripemd128_compress (ctx, ctx->buf)) != CRYPT_OK) {
                 return err;
              }
              ctx->length += 8*_RMD128_BLOCK_SIZE;
              ctx->curlen = 0;
           }
       }
    }
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param ctx  The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
int ripemd128_done(ripemd128_context* ctx, unsigned char *out)
{
    int i;

    if (ctx->curlen >= sizeof(ctx->buf)) {
       return CRYPT_INVALID_ARG;
    }


    /* increase the length of the message */
    ctx->length += ctx->curlen * 8;

    /* append the '1' bit */
    ctx->buf[ctx->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (ctx->curlen > 56) {
        while (ctx->curlen < 64) {
            ctx->buf[ctx->curlen++] = (unsigned char)0;
        }
        ripemd128_compress(ctx, ctx->buf);
        ctx->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (ctx->curlen < 56) {
        ctx->buf[ctx->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(ctx->length, ctx->buf+56);
    ripemd128_compress(ctx, ctx->buf);

    /* copy output */
    for (i = 0; i < 4; i++) {
        STORE32L(ctx->state[i], out+(4*i));
    }
#ifdef LTC_CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
   return CRYPT_OK;  
}

int ripemd128(const unsigned char *in, unsigned long inlen, unsigned char *out)
{
	ripemd128_context ctx;
	ripemd128_init(&ctx);
	ripemd128_process(&ctx, in, inlen);
	ripemd128_done(&ctx, out);
	return CRYPT_OK;
}

int ripemd128_hmac_init(ripemd128_context* ctx, const unsigned char * key, int keylen)
{
	memset( ctx->ipad, 0x36, _RMD128_BLOCK_SIZE );
	memset( ctx->opad, 0x5c, _RMD128_BLOCK_SIZE );

	unsigned char key_temp[_RMD128_BLOCK_SIZE];

	if (keylen > _RMD128_BLOCK_SIZE)
	{
		ripemd128(key, keylen, key_temp);
		keylen = _RMD128_DIGEST_SIZE;
	}
	else
	{
		memcpy(key_temp, key, keylen);
	}

	for ( int i = 0; i < keylen; i++ )
	{
		ctx->ipad[i] ^= key_temp[i];
		ctx->opad[i] ^= key_temp[i];
	}

	ripemd128_init(ctx);
	ripemd128_process(ctx, ctx->ipad, _RMD128_BLOCK_SIZE);

	return CRYPT_OK;
}

int ripemd128_hmac_process (ripemd128_context* ctx, const unsigned char *in, unsigned long inlen)
{
	return ripemd128_process(ctx, in, inlen);
}

int ripemd128_hmac_done(ripemd128_context* ctx, unsigned char *out)
{
	unsigned char temp[_RMD128_DIGEST_SIZE];
	ripemd128_done(ctx, temp);

	ripemd128_init(ctx);
	ripemd128_process(ctx, ctx->opad, _RMD128_BLOCK_SIZE);
	ripemd128_process(ctx, temp, _RMD128_DIGEST_SIZE);
	ripemd128_done(ctx, out);

	return CRYPT_OK;
}