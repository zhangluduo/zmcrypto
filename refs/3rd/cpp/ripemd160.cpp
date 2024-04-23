
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

/* Implementation of LTC_RIPEMD-160 based on the source by Antoon Bosselaers, ESAT-COSIC
 *
 * This source has been radically overhauled to be portable and work within
 * the LibTomCrypt API by Tom St Denis
 */

#include "ripemd160.h"
#include <memory.h>
#include <stdlib.h>

#ifndef MAX
   #define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
   #define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

/* the five basic functions F(), G() and H() */
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))

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

/* the ten basic operations FF() through III() */
#define FF(a, b, c, d, e, x, s)        \
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define GG(a, b, c, d, e, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define HH(a, b, c, d, e, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define II(a, b, c, d, e, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define JJ(a, b, c, d, e, x, s)        \
      (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define FFF(a, b, c, d, e, x, s)        \
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define GGG(a, b, c, d, e, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define HHH(a, b, c, d, e, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define III(a, b, c, d, e, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

#define JJJ(a, b, c, d, e, x, s)        \
      (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROLc((a), (s)) + (e);\
      (c) = ROLc((c), 10);

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

static int ripemd160_compress(ripemd160_context* ctx, unsigned char *buf)
{
   ulong32 aa,bb,cc,dd,ee,aaa,bbb,ccc,ddd,eee,X[16];
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
   ee = eee = ctx->state[4];

   /* round 1 */
   FF(aa, bb, cc, dd, ee, X[ 0], 11);
   FF(ee, aa, bb, cc, dd, X[ 1], 14);
   FF(dd, ee, aa, bb, cc, X[ 2], 15);
   FF(cc, dd, ee, aa, bb, X[ 3], 12);
   FF(bb, cc, dd, ee, aa, X[ 4],  5);
   FF(aa, bb, cc, dd, ee, X[ 5],  8);
   FF(ee, aa, bb, cc, dd, X[ 6],  7);
   FF(dd, ee, aa, bb, cc, X[ 7],  9);
   FF(cc, dd, ee, aa, bb, X[ 8], 11);
   FF(bb, cc, dd, ee, aa, X[ 9], 13);
   FF(aa, bb, cc, dd, ee, X[10], 14);
   FF(ee, aa, bb, cc, dd, X[11], 15);
   FF(dd, ee, aa, bb, cc, X[12],  6);
   FF(cc, dd, ee, aa, bb, X[13],  7);
   FF(bb, cc, dd, ee, aa, X[14],  9);
   FF(aa, bb, cc, dd, ee, X[15],  8);
                             
   /* round 2 */
   GG(ee, aa, bb, cc, dd, X[ 7],  7);
   GG(dd, ee, aa, bb, cc, X[ 4],  6);
   GG(cc, dd, ee, aa, bb, X[13],  8);
   GG(bb, cc, dd, ee, aa, X[ 1], 13);
   GG(aa, bb, cc, dd, ee, X[10], 11);
   GG(ee, aa, bb, cc, dd, X[ 6],  9);
   GG(dd, ee, aa, bb, cc, X[15],  7);
   GG(cc, dd, ee, aa, bb, X[ 3], 15);
   GG(bb, cc, dd, ee, aa, X[12],  7);
   GG(aa, bb, cc, dd, ee, X[ 0], 12);
   GG(ee, aa, bb, cc, dd, X[ 9], 15);
   GG(dd, ee, aa, bb, cc, X[ 5],  9);
   GG(cc, dd, ee, aa, bb, X[ 2], 11);
   GG(bb, cc, dd, ee, aa, X[14],  7);
   GG(aa, bb, cc, dd, ee, X[11], 13);
   GG(ee, aa, bb, cc, dd, X[ 8], 12);

   /* round 3 */
   HH(dd, ee, aa, bb, cc, X[ 3], 11);
   HH(cc, dd, ee, aa, bb, X[10], 13);
   HH(bb, cc, dd, ee, aa, X[14],  6);
   HH(aa, bb, cc, dd, ee, X[ 4],  7);
   HH(ee, aa, bb, cc, dd, X[ 9], 14);
   HH(dd, ee, aa, bb, cc, X[15],  9);
   HH(cc, dd, ee, aa, bb, X[ 8], 13);
   HH(bb, cc, dd, ee, aa, X[ 1], 15);
   HH(aa, bb, cc, dd, ee, X[ 2], 14);
   HH(ee, aa, bb, cc, dd, X[ 7],  8);
   HH(dd, ee, aa, bb, cc, X[ 0], 13);
   HH(cc, dd, ee, aa, bb, X[ 6],  6);
   HH(bb, cc, dd, ee, aa, X[13],  5);
   HH(aa, bb, cc, dd, ee, X[11], 12);
   HH(ee, aa, bb, cc, dd, X[ 5],  7);
   HH(dd, ee, aa, bb, cc, X[12],  5);

   /* round 4 */
   II(cc, dd, ee, aa, bb, X[ 1], 11);
   II(bb, cc, dd, ee, aa, X[ 9], 12);
   II(aa, bb, cc, dd, ee, X[11], 14);
   II(ee, aa, bb, cc, dd, X[10], 15);
   II(dd, ee, aa, bb, cc, X[ 0], 14);
   II(cc, dd, ee, aa, bb, X[ 8], 15);
   II(bb, cc, dd, ee, aa, X[12],  9);
   II(aa, bb, cc, dd, ee, X[ 4],  8);
   II(ee, aa, bb, cc, dd, X[13],  9);
   II(dd, ee, aa, bb, cc, X[ 3], 14);
   II(cc, dd, ee, aa, bb, X[ 7],  5);
   II(bb, cc, dd, ee, aa, X[15],  6);
   II(aa, bb, cc, dd, ee, X[14],  8);
   II(ee, aa, bb, cc, dd, X[ 5],  6);
   II(dd, ee, aa, bb, cc, X[ 6],  5);
   II(cc, dd, ee, aa, bb, X[ 2], 12);

   /* round 5 */
   JJ(bb, cc, dd, ee, aa, X[ 4],  9);
   JJ(aa, bb, cc, dd, ee, X[ 0], 15);
   JJ(ee, aa, bb, cc, dd, X[ 5],  5);
   JJ(dd, ee, aa, bb, cc, X[ 9], 11);
   JJ(cc, dd, ee, aa, bb, X[ 7],  6);
   JJ(bb, cc, dd, ee, aa, X[12],  8);
   JJ(aa, bb, cc, dd, ee, X[ 2], 13);
   JJ(ee, aa, bb, cc, dd, X[10], 12);
   JJ(dd, ee, aa, bb, cc, X[14],  5);
   JJ(cc, dd, ee, aa, bb, X[ 1], 12);
   JJ(bb, cc, dd, ee, aa, X[ 3], 13);
   JJ(aa, bb, cc, dd, ee, X[ 8], 14);
   JJ(ee, aa, bb, cc, dd, X[11], 11);
   JJ(dd, ee, aa, bb, cc, X[ 6],  8);
   JJ(cc, dd, ee, aa, bb, X[15],  5);
   JJ(bb, cc, dd, ee, aa, X[13],  6);

   /* parallel round 1 */
   JJJ(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, X[14],  9);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
   JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
   JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
   JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
   JJJ(ccc, ddd, eee, aaa, bbb, X[13],  7);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
   JJJ(aaa, bbb, ccc, ddd, eee, X[15],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
   JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
   JJJ(aaa, bbb, ccc, ddd, eee, X[12],  6);

   /* parallel round 2 */
   III(eee, aaa, bbb, ccc, ddd, X[ 6],  9); 
   III(ddd, eee, aaa, bbb, ccc, X[11], 13);
   III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
   III(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
   III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
   III(eee, aaa, bbb, ccc, ddd, X[13],  8);
   III(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
   III(ccc, ddd, eee, aaa, bbb, X[10], 11);
   III(bbb, ccc, ddd, eee, aaa, X[14],  7);
   III(aaa, bbb, ccc, ddd, eee, X[15],  7);
   III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
   III(ddd, eee, aaa, bbb, ccc, X[12],  7);
   III(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
   III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
   III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
   III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

   /* parallel round 3 */
   HHH(ddd, eee, aaa, bbb, ccc, X[15],  9);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
   HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
   HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
   HHH(ddd, eee, aaa, bbb, ccc, X[14],  6);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
   HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
   HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
   HHH(ddd, eee, aaa, bbb, ccc, X[12],  5);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
   HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
   HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
   HHH(ddd, eee, aaa, bbb, ccc, X[13],  5);

   /* parallel round 4 */   
   GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
   GGG(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
   GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
   GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
   GGG(bbb, ccc, ddd, eee, aaa, X[15],  6);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
   GGG(ddd, eee, aaa, bbb, ccc, X[12],  9);
   GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
   GGG(bbb, ccc, ddd, eee, aaa, X[13],  9);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
   GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
   GGG(ccc, ddd, eee, aaa, bbb, X[14],  8);

   /* parallel round 5 */
   FFF(bbb, ccc, ddd, eee, aaa, X[12] ,  8);
   FFF(aaa, bbb, ccc, ddd, eee, X[15] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, X[10] , 12);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 4] ,  9);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 1] , 12);
   FFF(bbb, ccc, ddd, eee, aaa, X[ 5] ,  5);
   FFF(aaa, bbb, ccc, ddd, eee, X[ 8] , 14);
   FFF(eee, aaa, bbb, ccc, ddd, X[ 7] ,  6);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 6] ,  8);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 2] , 13);
   FFF(bbb, ccc, ddd, eee, aaa, X[13] ,  6);
   FFF(aaa, bbb, ccc, ddd, eee, X[14] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, X[ 0] , 15);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 3] , 13);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 9] , 11);
   FFF(bbb, ccc, ddd, eee, aaa, X[11] , 11);

   /* combine results */
   ddd += cc + ctx->state[1];               /* final result for ctx->state[0] */
   ctx->state[1] = ctx->state[2] + dd + eee;
   ctx->state[2] = ctx->state[3] + ee + aaa;
   ctx->state[3] = ctx->state[4] + aa + bbb;
   ctx->state[4] = ctx->state[0] + bb + ccc;
   ctx->state[0] = ddd;

   return CRYPT_OK;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int ripemd160_init(ripemd160_context* ctx)
{
   ctx->state[0] = 0x67452301UL;
   ctx->state[1] = 0xefcdab89UL;
   ctx->state[2] = 0x98badcfeUL;
   ctx->state[3] = 0x10325476UL;
   ctx->state[4] = 0xc3d2e1f0UL;
   ctx->curlen   = 0;
   ctx->length   = 0; 
   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int ripemd160_process (ripemd160_context* ctx, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;

    if (ctx->curlen > sizeof(ctx->buf)) {
       return CRYPT_INVALID_ARG;
    }
    while (inlen > 0) {
        if (ctx->curlen == 0 && inlen >= _RMD160_BLOCK_SIZE) {
           if ((err = ripemd160_compress (ctx, (unsigned char *)in)) != CRYPT_OK) {
              return err;
           }
           ctx->length += _RMD160_BLOCK_SIZE * 8;
           in += _RMD160_BLOCK_SIZE;
           inlen -= _RMD160_BLOCK_SIZE;
        } else {
           n = MIN(inlen, (_RMD160_BLOCK_SIZE - ctx->curlen));
           memcpy(ctx->buf + ctx->curlen, in, (size_t)n);
           ctx->curlen += n;
           in += n;
           inlen -= n;
           if (ctx->curlen == _RMD160_BLOCK_SIZE) {
              if ((err = ripemd160_compress (ctx, ctx->buf)) != CRYPT_OK) {
                 return err;
              }
              ctx->length += 8 * _RMD160_BLOCK_SIZE;
              ctx->curlen = 0;
           }
       }
    }
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
int ripemd160_done(ripemd160_context* ctx, unsigned char *out)
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
        ripemd160_compress(ctx, ctx->buf);
        ctx->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (ctx->curlen < 56) {
        ctx->buf[ctx->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(ctx->length, ctx->buf+56);
    ripemd160_compress(ctx, ctx->buf);

    /* copy output */
    for (i = 0; i < 5; i++) {
        STORE32L(ctx->state[i], out+(4*i));
    }
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(hash_state));
#endif
    return CRYPT_OK;
}

int ripemd160(const unsigned char *in, unsigned long inlen, unsigned char *out)
{
	ripemd160_context ctx;
	ripemd160_init(&ctx);
	ripemd160_process(&ctx, in, inlen);
	ripemd160_done(&ctx, out);
	return CRYPT_OK;
}

int ripemd160_hmac_init(ripemd160_context* ctx, const unsigned char * key, int keylen)
{
	memset( ctx->ipad, 0x36, _RMD160_BLOCK_SIZE );
	memset( ctx->opad, 0x5c, _RMD160_BLOCK_SIZE );

	unsigned char key_temp[_RMD160_BLOCK_SIZE];

	if (keylen > _RMD160_BLOCK_SIZE)
	{
		ripemd160(key, keylen, key_temp);
		keylen = _RMD160_DIGEST_SIZE;
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

	ripemd160_init(ctx);
	ripemd160_process(ctx, ctx->ipad, _RMD160_BLOCK_SIZE);

	return CRYPT_OK;
}

int ripemd160_hmac_process (ripemd160_context* ctx, const unsigned char *in, unsigned long inlen)
{
	return ripemd160_process(ctx, in, inlen);
}

int ripemd160_hmac_done(ripemd160_context* ctx, unsigned char *out)
{
	unsigned char temp[_RMD160_DIGEST_SIZE];
	ripemd160_done(ctx, temp);

	ripemd160_init(ctx);
	ripemd160_process(ctx, ctx->opad, _RMD160_BLOCK_SIZE);
	ripemd160_process(ctx, temp, _RMD160_DIGEST_SIZE);
	ripemd160_done(ctx, out);

	return CRYPT_OK;
}