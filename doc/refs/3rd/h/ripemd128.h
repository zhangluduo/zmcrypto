// 该代码提取自libtomcrypt-1.17
// __张鲁夺, 2013-09-05
// support@zhangluduo.com

// ripemd128.h: interface for the ripemd128 class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_RIPEMD128_H__67F3E0C7_DDD1_4417_8DF1_F6E08F321A0E__INCLUDED_)
#define AFX_RIPEMD128_H__67F3E0C7_DDD1_4417_8DF1_F6E08F321A0E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/* fix for MSVC ...evil! */
#ifdef _MSC_VER
   #define CONST64(n) n ## ui64
   typedef unsigned __int64 ulong64;
#else
   #define CONST64(n) n ## ULL
   typedef unsigned long long ulong64;
#endif

/* this is the "32-bit at least" data type 
 * Re-define it to suit your platform but it must be at least 32-bits 
 */
#if defined(__x86_64__) || (defined(__sparc__) && defined(__arch64__))
   typedef unsigned ulong32;
#else
   typedef unsigned long ulong32;
#endif

#if !defined __CRYPT_RESULT_VALUE
#define __CRYPT_RESULT_VALUE
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
#endif // __CRYPT_RESULT_VALUE

#define _RMD128_DIGEST_SIZE 16
#define _RMD128_BLOCK_SIZE 64

typedef struct {
    ulong64 length;
    unsigned char buf[_RMD128_BLOCK_SIZE];
    ulong32 curlen, state[4];

	unsigned char ipad[_RMD128_BLOCK_SIZE];
	unsigned char opad[_RMD128_BLOCK_SIZE];

} ripemd128_context;

/**
   Initialize the hash state
   @param ctx   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int ripemd128_init(ripemd128_context* ctx);

/**
   Process a block of memory though the hash
   @param ctx     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int ripemd128_process (ripemd128_context* ctx, const unsigned char *in, unsigned long inlen);

/**
   Terminate the hash to get the digest
   @param ctx  The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
int ripemd128_done(ripemd128_context* ctx, unsigned char *out);

// ------------------------------------------------------------------------------
// The HMAC functions implementation by Zhang Luduo (http://www.ZhangLuduo.com)
// support@ZhangLuduo.com
int ripemd128(const unsigned char *in, unsigned long inlen, unsigned char *out);
int ripemd128_hmac_init(ripemd128_context* ctx, const unsigned char * key, int keylen);
int ripemd128_hmac_process (ripemd128_context* ctx, const unsigned char *in, unsigned long inlen);
int ripemd128_hmac_done(ripemd128_context*  ctx, unsigned char *out);

#endif // !defined(AFX_RIPEMD128_H__67F3E0C7_DDD1_4417_8DF1_F6E08F321A0E__INCLUDED_)
