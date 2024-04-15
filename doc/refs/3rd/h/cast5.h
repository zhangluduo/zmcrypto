// Cast5.h: interface for the Cast5 class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_CAST5_H__A3FB6243_4390_4A8F_9A4B_5518C3C245DB__INCLUDED_)
#define AFX_CAST5_H__A3FB6243_4390_4A8F_9A4B_5518C3C245DB__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/* this is the "32-bit at least" data type 
 * Re-define it to suit your platform but it must be at least 32-bits 
 */
#if defined(__x86_64__) || (defined(__sparc__) && defined(__arch64__))
   typedef unsigned ulong32;
#else
   typedef unsigned long ulong32;
#endif

/* extract a byte portably */
	//#ifdef _MSC_VER
	//   #define byte(x, n) ((unsigned char)((x) >> (8 * (n))))
	//#else
	//   #define byte(x, n) (((x) >> (8 * (n))) & 255)
	//#endif 

#if defined byte
	#pragma push_macro("byte")
	#undef byte
	#define byte(x,n)   ((unsigned char)((x) >> (8 * n)))
    #pragma pop_macro("byte")
#else
#define byte(x,n)   ((unsigned char)((x) >> (8 * n)))
#endif

#if !defined __CRYPT_RESULT_VALUE
#define __CRYPT_RESULT_VALUE

#ifdef _MSC_VER

#  include <stdlib.h>
#  pragma intrinsic(_lrotr,_lrotl)
#  define rotr(x,n) _lrotr(x,n)
#  define rotl(x,n) _lrotl(x,n)

#else

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

#define _rotr rotr
#define _rotl rotl

#define _lrotr rotr
#define _lrotl rotl

#endif

/* error codes [will be expanded in future releases] */
enum {
   CRYPT_OK=0,             /* Result OK */
   CRYPT_ERROR,            /* Generic Error */
   CRYPT_NOP,              /* Not a failure but no operation was performed */

   CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
   CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
   CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

   CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
   CRYPT_INVALID_PACKET,   /* Invalid input packet given */

   CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
   CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

   CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
   CRYPT_INVALID_HASH,     /* Invalid hash specified */
   CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

   CRYPT_MEM,              /* Out of memory */

   CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
   CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

   CRYPT_INVALID_ARG,      /* Generic invalid argument */
   CRYPT_FILE_NOTFOUND,    /* File Not Found */

   CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */
   CRYPT_PK_INVALID_SYSTEM,/* Invalid PK system specified */
   CRYPT_PK_DUP,           /* Duplicate key already in key ring */
   CRYPT_PK_NOT_FOUND,     /* Key not found in keyring */
   CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

   CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
   CRYPT_PK_INVALID_PADDING /* Invalid padding on input */
};
#endif //__CRYPT_RESULT_VALUE

struct cast5_key {
    ulong32 K[32], keylen;
};

typedef cast5_key cast5_context;

#define CAST5_ENCRYPT     1
#define CAST5_DECRYPT     0

#define XMEMCPY  memcpy

/**
  Encrypts a block of text with LTC_CAST5
  @param pt The input plaintext (8 bytes)
  @param ct The output ciphertext (8 bytes)
  @param skey The key as scheduled
*/

int cast5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, cast5_key *skey);

/**
  Decrypts a block of text with LTC_CAST5
  @param ct The input ciphertext (8 bytes)
  @param pt The output plaintext (8 bytes)
  @param skey The key as scheduled 
*/

int cast5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, cast5_key *skey);

 /**
    Initialize the LTC_CAST5 block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */

int cast5_setup(const unsigned char *key, int keylen, int num_rounds, cast5_key *skey);

// Add by Zhang Luduo (http://www.ZhangLuduo.com/), 2014-09-11
int cast5_crypt_cbc( cast5_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output );

// Add by Zhang Luduo (http://www.ZhangLuduo.com/), 2014-09-11
int cast5_crypt_cfb64( cast5_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[8],
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo (http://www.ZhangLuduo.com/), 2014-09-11
int cast5_crypt_ofb( cast5_context *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[8], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo (http://www.ZhangLuduo.com/), 2014-09-11
int cast5_crypt_ctr( cast5_context *ctx,
                       int length,
                       int *nc_off,
                       unsigned char nonce_counter[8],
                       const unsigned char *input,
                       unsigned char *output );

#endif // !defined(AFX_CAST5_H__A3FB6243_4390_4A8F_9A4B_5518C3C245DB__INCLUDED_)
