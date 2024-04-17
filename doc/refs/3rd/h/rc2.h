
// 该代码提取自libtomcrypt-1.17
// __张鲁夺, 2013-10-25
// support@zhangluduo.com

#if !defined(AFX_RC2_H__EC36E2F9_CCD2_42F6_AD02_7A1332863F13__INCLUDED_)
#define AFX_RC2_H__EC36E2F9_CCD2_42F6_AD02_7A1332863F13__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#if !defined __CRYPT_RESULT_VALUE
#define __CRYPT_RESULT_VALUE

#include <string.h>

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
#endif // __CRYPT_RESULT_VALUE

struct rc2_key {
   unsigned K[64];
};

typedef rc2_key rc2_context;

#define RC2_ENCRYPT     1
#define RC2_DECRYPT     0

 /**
    Initialize the LTC_RC2 block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int rc2_setup(const unsigned char *key, int keylen, int num_rounds, rc2_key *skey);

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
int rc2_ecb_encrypt( const unsigned char *pt, unsigned char *ct, rc2_key *skey);

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
int rc2_ecb_decrypt( const unsigned char *ct, unsigned char *pt, rc2_key *skey);





// Add by Zhang Luduo, 2014-09-04
int rc2_crypt_cbc( rc2_context *ctx,
                     int mode,
                     int length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output );

// Add by Zhang Luduo, 2014-09-04
int rc2_crypt_cfb64( rc2_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[8],
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo, 2014-09-04
int rc2_crypt_ofb( rc2_context *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[8], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo, 2014-09-04
int rc2_crypt_ctr( rc2_context *ctx,
                       int length,
                       int *nc_off,
                       unsigned char nonce_counter[8],
                       const unsigned char *input,
                       unsigned char *output );










#endif // !defined(AFX_RC2_H__EC36E2F9_CCD2_42F6_AD02_7A1332863F13__INCLUDED_)
