#if !defined(AFX_SAFER_H__FD999E58_2E8E_440F_93C1_EC003F54B93D__INCLUDED_)
#define AFX_SAFER_H__FD999E58_2E8E_440F_93C1_EC003F54B93D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string.h>

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
#endif //__CRYPT_RESULT_VALUE

#define SAFER_ENCRYPT     1
#define SAFER_DECRYPT     0

#define LTC_SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define LTC_SAFER_K128_DEFAULT_NOF_ROUNDS   10
#define LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS    8
#define LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS  10
#define LTC_SAFER_MAX_NOF_ROUNDS            13
#define LTC_SAFER_BLOCK_LEN                  8
#define LTC_SAFER_KEY_LEN     (1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS))

typedef unsigned char safer_key_t[LTC_SAFER_KEY_LEN];
struct safer_key { safer_key_t key; };

int safer_k64_setup(const unsigned char *key, int keylen, int numrounds, safer_key *skey);
   
int safer_sk64_setup(const unsigned char *key, int keylen, int numrounds, safer_key *skey);

int safer_k128_setup(const unsigned char *key, int keylen, int numrounds, safer_key *skey);

int safer_sk128_setup(const unsigned char *key, int keylen, int numrounds, safer_key *skey);

int safer_ecb_encrypt(const unsigned char *block_in, unsigned char *block_out, safer_key *skey);
  
int safer_ecb_decrypt(const unsigned char *block_in, unsigned char *block_out, safer_key *skey);

// Add by Zhang Luduo, 2014-09-29
int safer_crypt_cbc( safer_key *ctx,
                    int mode,
                    int length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output );

// Add by Zhang Luduo, 2014-09-29
int safer_crypt_cfb64( safer_key *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[8],
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo, 2014-09-29
int safer_crypt_ofb( safer_key *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[8], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo, 2014-09-29
int safer_crypt_ctr( safer_key *ctx,
                       int length,
                       int *nc_off,
                       unsigned char nonce_counter[8],
                       const unsigned char *input,
                       unsigned char *output );

#endif // !defined(AFX_SAFER_H__FD999E58_2E8E_440F_93C1_EC003F54B93D__INCLUDED_)
