
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

#include "rc6.h"
#include <memory.h>
#include <stdlib.h>

#define BSWAP(x)  ( ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL)  | \
                    ((x>>8)&0x0000FF00UL)  | ((x<<8)&0x00FF0000UL) )

#ifndef MAX
   #define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
   #define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

//#pragma intrinsic(_lrotr,_lrotl)
#define ROR(x,n) _lrotr(x,n)
#define ROL(x,n) _lrotl(x,n)
#define RORc(x,n) _lrotr(x,n)
#define ROLc(x,n) _lrotl(x,n)

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
           ((unsigned long)((y)[2] & 255)<<16) | \
           ((unsigned long)((y)[1] & 255)<<8)  | \
           ((unsigned long)((y)[0] & 255)); }

#define STORE32L(x, y)        \
     { ulong32  __t = (x); memcpy(y, &__t, 4); }

static const ulong32 stab[44] = {
0xb7e15163UL, 0x5618cb1cUL, 0xf45044d5UL, 0x9287be8eUL, 0x30bf3847UL, 0xcef6b200UL, 0x6d2e2bb9UL, 0x0b65a572UL,
0xa99d1f2bUL, 0x47d498e4UL, 0xe60c129dUL, 0x84438c56UL, 0x227b060fUL, 0xc0b27fc8UL, 0x5ee9f981UL, 0xfd21733aUL,
0x9b58ecf3UL, 0x399066acUL, 0xd7c7e065UL, 0x75ff5a1eUL, 0x1436d3d7UL, 0xb26e4d90UL, 0x50a5c749UL, 0xeedd4102UL,
0x8d14babbUL, 0x2b4c3474UL, 0xc983ae2dUL, 0x67bb27e6UL, 0x05f2a19fUL, 0xa42a1b58UL, 0x42619511UL, 0xe0990ecaUL,
0x7ed08883UL, 0x1d08023cUL, 0xbb3f7bf5UL, 0x5976f5aeUL, 0xf7ae6f67UL, 0x95e5e920UL, 0x341d62d9UL, 0xd254dc92UL,
0x708c564bUL, 0x0ec3d004UL, 0xacfb49bdUL, 0x4b32c376UL };

 /**
    Initialize the LTC_RC6 block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int rc6_setup(const unsigned char *key, int keylen, int num_rounds, rc6_key *skey)
{
	ulong32 L[64], S[50], A, B, i, j, v, s, l;

	/* test parameters */
	if (num_rounds != 0 && num_rounds != 20) { 
	   return CRYPT_INVALID_ROUNDS;
	}

	/* key must be between 64 and 1024 bits */
	//if (keylen < 8 || keylen > 128) {
	//   return CRYPT_INVALID_KEYSIZE;
	//}

	// Modify by Zhang Luduo, 2020-04-12
	if (keylen < 16 || keylen > 32) {
	   return CRYPT_INVALID_KEYSIZE;
	}

	/* copy the key into the L array */
	for (A = i = j = 0; i < (ulong32)keylen; ) { 
		A = (A << 8) | ((ulong32)(key[i++] & 255));
		if (!(i & 3)) {
		   L[j++] = BSWAP(A);
		   A = 0;
		}
	}

	/* handle odd sized keys */
	if (keylen & 3) { 
	   A <<= (8 * (4 - (keylen&3))); 
	   L[j++] = BSWAP(A); 
	}

	/* setup the S array */
	memcpy(S, stab, 44 * sizeof(stab[0]));

	/* mix buffer */
	s = 3 * MAX(44, j);
	l = j;
	for (A = B = i = j = v = 0; v < s; v++) { 
		A = S[i] = ROLc(S[i] + A + B, 3);
		B = L[j] = ROL(L[j] + A + B, (A+B));
		if (++i == 44) { i = 0; }
		if (++j == l)  { j = 0; }
	}

	/* copy to key */
	for (i = 0; i < 44; i++) { 
		skey->K[i] = S[i];
	}
	return CRYPT_OK;
}


/**
  Encrypts a block of text with LTC_RC6
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
*/
int rc6_ecb_encrypt(const unsigned char *pt, unsigned char *ct, rc6_key *skey)
{
   ulong32 a,b,c,d,t,u, *K;
   int r;

   LOAD32L(a,&pt[0]);
   LOAD32L(b,&pt[4]);
   LOAD32L(c,&pt[8]);
   LOAD32L(d,&pt[12]);

   b += skey->K[0];
   d += skey->K[1];

#define RND(a,b,c,d) \
	   t = (b * (b + b + 1)); t = ROLc(t, 5); \
	   u = (d * (d + d + 1)); u = ROLc(u, 5); \
	   a = ROL(a^t,u) + K[0];                \
	   c = ROL(c^u,t) + K[1]; K += 2;   

   K = skey->K + 2;
   for (r = 0; r < 20; r += 4) {
	   RND(a,b,c,d);
	   RND(b,c,d,a);
	   RND(c,d,a,b);
	   RND(d,a,b,c);
   }

#undef RND

   a += skey->K[42];
   c += skey->K[43];

   STORE32L(a,&ct[0]);
   STORE32L(b,&ct[4]);
   STORE32L(c,&ct[8]);
   STORE32L(d,&ct[12]);
   return CRYPT_OK;
}

/**
  Decrypts a block of text with LTC_RC6
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled 
*/
int rc6_ecb_decrypt(const unsigned char *ct, unsigned char *pt, rc6_key *skey)
{
   ulong32 a,b,c,d,t,u, *K;
   int r;

   LOAD32L(a,&ct[0]);
   LOAD32L(b,&ct[4]);
   LOAD32L(c,&ct[8]);
   LOAD32L(d,&ct[12]);

   a -= skey->K[42];
   c -= skey->K[43];

#define RND(a,b,c,d) \
	   t = (b * (b + b + 1)); t = ROLc(t, 5); \
	   u = (d * (d + d + 1)); u = ROLc(u, 5); \
	   c = ROR(c - K[1], t) ^ u; \
	   a = ROR(a - K[0], u) ^ t; K -= 2;

   K = skey->K + 40;

   for (r = 0; r < 20; r += 4) {
	   RND(d,a,b,c);
	   RND(c,d,a,b);
	   RND(b,c,d,a);
	   RND(a,b,c,d);
   }

#undef RND

   b -= skey->K[0];
   d -= skey->K[1];

   STORE32L(a,&pt[0]);
   STORE32L(b,&pt[4]);
   STORE32L(c,&pt[8]);
   STORE32L(d,&pt[12]);

   return CRYPT_OK;
}

int rc6_crypt_cbc( rc6_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

    if(length % 16)
        return 1;//( POLARSSL_ERR_XTEA_INVALID_INPUT_LENGTH );

    if( mode == RC6_DECRYPT ) 
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
			rc6_ecb_decrypt(input, output, ctx);

            for(i = 0; i < 16; i++) 
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    } 
    else 
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

			rc6_ecb_encrypt(output, output, ctx);
            memcpy( iv, output, 16 );
            
            input  += 16;
            output += 16;
            length -= 16;
        }
    }

    return( 0 );
}

int rc6_crypt_cfb128( rc6_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    int n = *iv_off;

    if( mode == RC6_ENCRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
				rc6_ecb_encrypt(iv, iv, ctx);

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = (n + 1) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                rc6_ecb_encrypt(iv, iv, ctx);

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = (n + 1) & 0x0F;
        }
    }

    *iv_off = n;

	return 0;
}

int rc6_crypt_ofb( rc6_context *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[16], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output )
{
	unsigned int n = *iv_off; 

	while (length--) {  
		if (n == 0) {
			rc6_ecb_encrypt( iv, iv, ctx);
		}  
		*(output++) = *(input++) ^ iv[n];  
		n = (n + 1) % 16;  
	}  

	*iv_off = n;

	return 0;
}

int rc6_crypt_ctr( rc6_context *ctx,
                       int length,
                       int *nc_off,
                       unsigned char nonce_counter[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int n = *nc_off;
	unsigned char temp[16];

    while( length-- )
    {
        if( n == 0 ) {
            rc6_ecb_encrypt( nonce_counter, temp, ctx );

            for( int i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        int c = *input++;
        *output++ = (unsigned char)( c ^ temp[n] );

        n = (n + 1) % 16;
    }

    *nc_off = n;

    return( 0 );
}

	//void main()
	//{
	//	rc6_context ctx;

	//	int r1 = rc6_setup((const unsigned char *)"aa", 2, 0, &ctx);

	//	unsigned char pt [] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	//	unsigned char ct[16];


	//	int r2 = rc6_ecb_encrypt(pt, ct, &ctx);

	//	int n = 0;
	//}
