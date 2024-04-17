
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
/**********************************************************************\
* To commemorate the 1996 RSA Data Security Conference, the following  *
* code is released into the public domain by its author.  Prost!       *
*                                                                      *
* This cipher uses 16-bit words and little-endian byte ordering.       *
* I wonder which processor it was optimized for?                       *
*                                                                      *
* Thanks to CodeView, SoftIce, and D86 for helping bring this code to  *
* the public.                                                          *
\**********************************************************************/

#include "rc2.h"

/* 256-entry permutation table, probably derived somehow from pi */
static const unsigned char permute[256] = {
        217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
        198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
         23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
        189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
         84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
         18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
        111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
        248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
          8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
        150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
        194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
        153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
         45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
        211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
         13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
        197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
};

 /**
    Initialize the LTC_RC2 block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */

int rc2_setup(const unsigned char *key, int keylen, int num_rounds, rc2_key *skey)
{
   unsigned char tmp[128];
   unsigned T8, TM;
   int i, bits;

/*
   if (keylen < 8 || keylen > 128) {
      return CRYPT_INVALID_KEYSIZE;
   }
*/

	// Modify by Zhang Luduo, 2020-03-23
   if (keylen < 1 || keylen > 128) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if (num_rounds != 0 && num_rounds != 16) {
      return CRYPT_INVALID_ROUNDS;
   }

   for (i = 0; i < keylen; i++) {
       tmp[i] = key[i] & 255;
   }

    /* Phase 1: Expand input key to 128 bytes */
    if (keylen < 128) {
        for (i = keylen; i < 128; i++) {
            tmp[i] = permute[(tmp[i - 1] + tmp[i - keylen]) & 255];
        }
    }
    
    /* Phase 2 - reduce effective key size to "bits" */
    bits = keylen<<3;
    T8   = (unsigned)(bits+7)>>3;
    TM   = (255 >> (unsigned)(7 & -bits));
    tmp[128 - T8] = permute[tmp[128 - T8] & TM];
    for (i = 127 - T8; i >= 0; i--) {
        tmp[i] = permute[tmp[i + 1] ^ tmp[i + T8]];
    }

    /* Phase 3 - copy to xkey in little-endian order */
    for (i = 0; i < 64; i++) {
        skey->K[i] =  (unsigned)tmp[2*i] + ((unsigned)tmp[2*i+1] << 8);
    }        

#ifdef LTC_CLEAN_STACK
    zeromem(tmp, sizeof(tmp));
#endif
    
    return CRYPT_OK;
}

/**********************************************************************\
* Encrypt an 8-byte block of plaintext using the given key.            *
\**********************************************************************/
/**
  Encrypts a block of text with LTC_RC2
  @param pt The input plaintext (8 bytes)
  @param ct The output ciphertext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int rc2_ecb_encrypt( const unsigned char *pt, unsigned char *ct, rc2_key *skey)
{
	unsigned x76, x54, x32, x10, i;

	x76 = ((unsigned)pt[7] << 8) + (unsigned)pt[6];
	x54 = ((unsigned)pt[5] << 8) + (unsigned)pt[4];
	x32 = ((unsigned)pt[3] << 8) + (unsigned)pt[2];
	x10 = ((unsigned)pt[1] << 8) + (unsigned)pt[0];

	for (i = 0; i < 16; i++) {
		x10 = (x10 + (x32 & ~x76) + (x54 & x76) + skey->K[4*i+0]) & 0xFFFF;
		x10 = ((x10 << 1) | (x10 >> 15));

		x32 = (x32 + (x54 & ~x10) + (x76 & x10) + skey->K[4*i+1]) & 0xFFFF;
		x32 = ((x32 << 2) | (x32 >> 14));

		x54 = (x54 + (x76 & ~x32) + (x10 & x32) + skey->K[4*i+2]) & 0xFFFF;
		x54 = ((x54 << 3) | (x54 >> 13));

		x76 = (x76 + (x10 & ~x54) + (x32 & x54) + skey->K[4*i+3]) & 0xFFFF;
		x76 = ((x76 << 5) | (x76 >> 11));

		if (i == 4 || i == 10) {
			x10 = (x10 + skey->K[x76 & 63]) & 0xFFFF;
			x32 = (x32 + skey->K[x10 & 63]) & 0xFFFF;
			x54 = (x54 + skey->K[x32 & 63]) & 0xFFFF;
			x76 = (x76 + skey->K[x54 & 63]) & 0xFFFF;
		}
	}

	ct[0] = (unsigned char)x10;
	ct[1] = (unsigned char)(x10 >> 8);
	ct[2] = (unsigned char)x32;
	ct[3] = (unsigned char)(x32 >> 8);
	ct[4] = (unsigned char)x54;
	ct[5] = (unsigned char)(x54 >> 8);
	ct[6] = (unsigned char)x76;
	ct[7] = (unsigned char)(x76 >> 8);

	return CRYPT_OK;
}

/**********************************************************************\
* Decrypt an 8-byte block of ciphertext using the given key.           *
\**********************************************************************/
/**
  Decrypts a block of text with LTC_RC2
  @param ct The input ciphertext (8 bytes)
  @param pt The output plaintext (8 bytes)
  @param skey The key as scheduled 
  @return CRYPT_OK if successful
*/
int rc2_ecb_decrypt( const unsigned char *ct, unsigned char *pt, rc2_key *skey)
{
	unsigned x76, x54, x32, x10;
	int i;

	x76 = ((unsigned)ct[7] << 8) + (unsigned)ct[6];
	x54 = ((unsigned)ct[5] << 8) + (unsigned)ct[4];
	x32 = ((unsigned)ct[3] << 8) + (unsigned)ct[2];
	x10 = ((unsigned)ct[1] << 8) + (unsigned)ct[0];

	for (i = 15; i >= 0; i--) {
		if (i == 4 || i == 10) {
			x76 = (x76 - skey->K[x54 & 63]) & 0xFFFF;
			x54 = (x54 - skey->K[x32 & 63]) & 0xFFFF;
			x32 = (x32 - skey->K[x10 & 63]) & 0xFFFF;
			x10 = (x10 - skey->K[x76 & 63]) & 0xFFFF;
		}

		x76 = ((x76 << 11) | (x76 >> 5));
		x76 = (x76 - ((x10 & ~x54) + (x32 & x54) + skey->K[4*i+3])) & 0xFFFF;

		x54 = ((x54 << 13) | (x54 >> 3));
		x54 = (x54 - ((x76 & ~x32) + (x10 & x32) + skey->K[4*i+2])) & 0xFFFF;

		x32 = ((x32 << 14) | (x32 >> 2));
		x32 = (x32 - ((x54 & ~x10) + (x76 & x10) + skey->K[4*i+1])) & 0xFFFF;

		x10 = ((x10 << 15) | (x10 >> 1));
		x10 = (x10 - ((x32 & ~x76) + (x54 & x76) + skey->K[4*i+0])) & 0xFFFF;
	}

	pt[0] = (unsigned char)x10;
	pt[1] = (unsigned char)(x10 >> 8);
	pt[2] = (unsigned char)x32;
	pt[3] = (unsigned char)(x32 >> 8);
	pt[4] = (unsigned char)x54;
	pt[5] = (unsigned char)(x54 >> 8);
	pt[6] = (unsigned char)x76;
	pt[7] = (unsigned char)(x76 >> 8);

	return CRYPT_OK;
}

int rc2_crypt_cbc( rc2_context *ctx,
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

    if( mode == RC2_DECRYPT ) 
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
			rc2_ecb_decrypt(input, output, ctx);

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

			rc2_ecb_encrypt(output, output, ctx);
            memcpy( iv, output, 8 );
            
            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}

// Add by Zhang Luduo, 2014-09-04
int rc2_crypt_cfb64( rc2_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[8],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    int n = *iv_off;

    if( mode == RC2_ENCRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
				rc2_ecb_encrypt(iv, iv, ctx);

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = (n + 1) % 8;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
				rc2_ecb_encrypt(iv, iv, ctx);

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = (n + 1) % 8;
        }
    }

    *iv_off = n;

    return( 0 );
}

int rc2_crypt_ofb( rc2_context *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[8], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output )
{
	unsigned int n = *iv_off; 

	while (length--) {  
		if (n == 0) {
			rc2_ecb_encrypt( iv, iv, ctx);
		}  
		*(output++) = *(input++) ^ iv[n];  
		n = (n + 1) % 8;  
	}  

	*iv_off = n;

	return 0;
}

int rc2_crypt_ctr( rc2_context *ctx,
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
            rc2_ecb_encrypt( nonce_counter, temp, ctx );

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