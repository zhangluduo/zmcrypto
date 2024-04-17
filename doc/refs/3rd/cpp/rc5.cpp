
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

#include "rc5.h"
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

static const ulong32 stab[50] = {
0xb7e15163UL, 0x5618cb1cUL, 0xf45044d5UL, 0x9287be8eUL, 0x30bf3847UL, 0xcef6b200UL, 0x6d2e2bb9UL, 0x0b65a572UL,
0xa99d1f2bUL, 0x47d498e4UL, 0xe60c129dUL, 0x84438c56UL, 0x227b060fUL, 0xc0b27fc8UL, 0x5ee9f981UL, 0xfd21733aUL,
0x9b58ecf3UL, 0x399066acUL, 0xd7c7e065UL, 0x75ff5a1eUL, 0x1436d3d7UL, 0xb26e4d90UL, 0x50a5c749UL, 0xeedd4102UL,
0x8d14babbUL, 0x2b4c3474UL, 0xc983ae2dUL, 0x67bb27e6UL, 0x05f2a19fUL, 0xa42a1b58UL, 0x42619511UL, 0xe0990ecaUL,
0x7ed08883UL, 0x1d08023cUL, 0xbb3f7bf5UL, 0x5976f5aeUL, 0xf7ae6f67UL, 0x95e5e920UL, 0x341d62d9UL, 0xd254dc92UL,
0x708c564bUL, 0x0ec3d004UL, 0xacfb49bdUL, 0x4b32c376UL, 0xe96a3d2fUL, 0x87a1b6e8UL, 0x25d930a1UL, 0xc410aa5aUL,
0x62482413UL, 0x007f9dccUL
};

 /**
    Initialize the LTC_RC5 block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int rc5_setup(const unsigned char *key, int keylen, int num_rounds, rc5_key *skey)
{
    ulong32 L[64], *S, A, B, i, j, v, s, t, l;
    
    /* test parameters */
    if (num_rounds == 0) { 
       num_rounds = 12; /*default_rounds*/;
    }

    if (num_rounds < 12 || num_rounds > 24) { 
       return CRYPT_INVALID_ROUNDS;
    }

    /* key must be between 64 and 1024 bits */
    //if (keylen < 8 || keylen > 128) {
    //   return CRYPT_INVALID_KEYSIZE;
    //}

    // Modify by Zhang Luduo, 2020-04-12
    if (keylen < 1 || keylen > 255) {
       return CRYPT_INVALID_KEYSIZE;
    }
    
    skey->rounds = num_rounds;
    S = skey->K;

    /* copy the key into the L array */
    for (A = i = j = 0; i < (ulong32)keylen; ) { 
        A = (A << 8) | ((ulong32)(key[i++] & 255));
        if ((i & 3) == 0) {
           L[j++] = BSWAP(A);
           A = 0;
        }
    }

    if ((keylen & 3) != 0) { 
       A <<= (ulong32)((8 * (4 - (keylen&3)))); 
       L[j++] = BSWAP(A);
    }

    /* setup the S array */
    t = (ulong32)(2 * (num_rounds + 1));
    memcpy(S, stab, t * sizeof(*S));

    /* mix buffer */
    s = 3 * MAX(t, j);
    l = j;
    for (A = B = i = j = v = 0; v < s; v++) { 
        A = S[i] = ROLc(S[i] + A + B, 3);
        B = L[j] = ROL(L[j] + A + B, (A+B));
        if (++i == t) { i = 0; }
        if (++j == l) { j = 0; }
    }
    return CRYPT_OK;
}


/**
  Encrypts a block of text with LTC_RC5
  @param pt The input plaintext (8 bytes)
  @param ct The output ciphertext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int rc5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, rc5_key *skey)
{
   ulong32 A, B, *K;
   int r;

   LOAD32L(A, &pt[0]);
   LOAD32L(B, &pt[4]);
   A += skey->K[0];
   B += skey->K[1];
   K  = skey->K + 2;

   if ((skey->rounds & 1) == 0) {
	  for (r = 0; r < skey->rounds; r += 2) {
		  A = ROL(A ^ B, B) + K[0];
		  B = ROL(B ^ A, A) + K[1];
		  A = ROL(A ^ B, B) + K[2];
		  B = ROL(B ^ A, A) + K[3];
		  K += 4;
	  }
   } else {
	  for (r = 0; r < skey->rounds; r++) {
		  A = ROL(A ^ B, B) + K[0];
		  B = ROL(B ^ A, A) + K[1];
		  K += 2;
	  }
   }
   STORE32L(A, &ct[0]);
   STORE32L(B, &ct[4]);

   return CRYPT_OK;
}


/**
  Decrypts a block of text with LTC_RC5
  @param ct The input ciphertext (8 bytes)
  @param pt The output plaintext (8 bytes)
  @param skey The key as scheduled 
  @return CRYPT_OK if successful
*/
int rc5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, rc5_key *skey)
{
   ulong32 A, B, *K;
   int r;

   LOAD32L(A, &ct[0]);
   LOAD32L(B, &ct[4]);
   K = skey->K + (skey->rounds << 1);

   if ((skey->rounds & 1) == 0) {
	   K -= 2;
	   for (r = skey->rounds - 1; r >= 0; r -= 2) {
		  B = ROR(B - K[3], A) ^ A;
		  A = ROR(A - K[2], B) ^ B;
		  B = ROR(B - K[1], A) ^ A;
		  A = ROR(A - K[0], B) ^ B;
		  K -= 4;
		}
   } else {
	  for (r = skey->rounds - 1; r >= 0; r--) {
		  B = ROR(B - K[1], A) ^ A;
		  A = ROR(A - K[0], B) ^ B;
		  K -= 2;
	  }
   }
   A -= skey->K[0];
   B -= skey->K[1];
   STORE32L(A, &pt[0]);
   STORE32L(B, &pt[4]);

   return CRYPT_OK;
}

int rc5_crypt_cbc( rc5_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[8];

    if(length % 8)
        return 1;//( POLARSSL_ERR_XTEA_INVALID_INPUT_LENGTH );

    if( mode == RC5_DECRYPT ) 
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
			rc5_ecb_decrypt(input, output, ctx);

            for(i = 0; i < 8; i++) 
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    } 
    else 
    {
        while( length > 0 )
        {
            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

			rc5_ecb_encrypt(output, output, ctx);
            memcpy( iv, output, 8 );
            
            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}

int rc5_crypt_cfb64( rc5_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[8],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    int n = *iv_off;

    if( mode == RC5_ENCRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
				rc5_ecb_encrypt(iv, iv, ctx);

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = (n + 1) % 8;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                rc5_ecb_encrypt(iv, iv, ctx);

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = (n + 1) % 8;
        }
    }

    *iv_off = n;

	return 0;
}

int rc5_crypt_ofb( rc5_context *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[8], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output )
{
	unsigned int n = *iv_off; 

	while (length--) {  
		if (n == 0) {
			rc5_ecb_encrypt( iv, iv, ctx);
		}  
		*(output++) = *(input++) ^ iv[n];  
		n = (n + 1) % 8;  
	}  

	*iv_off = n;

	return 0;
}

int rc5_crypt_ctr( rc5_context *ctx,
                       int length,
                       int *nc_off,
                       unsigned char nonce_counter[8],
                       const unsigned char *input,
                       unsigned char *output )
{
    int n = *nc_off;
	unsigned char temp[8];

    while( length-- )
    {
        if( n == 0 ) {
            rc5_ecb_encrypt( nonce_counter, temp, ctx );

            for( int i = 8; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        int c = *input++;
        *output++ = (unsigned char)( c ^ temp[n] );

        n = (n + 1) % 8;
    }

    *nc_off = n;

    return( 0 );
}

	//void main()
	//{
	//
	//	rc5_context ctx;
	//	int r1 = rc5_setup((const unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 255, 0, &ctx);
	//
	//	unsigned char pt[] = {0,1,2,3,4,5,6,7};
	//	unsigned char ct[8];
	//	int r2 = rc5_ecb_encrypt(pt, ct, &ctx);
	//	int n = 3;
	//}