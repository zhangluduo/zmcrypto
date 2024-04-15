#if !defined(AFX_SEED_H__1EA19BDD_FE81_4F6A_8F48_1A262265F86B__INCLUDED_)
#define AFX_SEED_H__1EA19BDD_FE81_4F6A_8F48_1A262265F86B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string.h>

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

struct kseed_key {
    ulong32 K[32], dK[32];
};

#define SEED_ENCRYPT     1
#define SEED_DECRYPT     0

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


 /**
    Initialize the SEED block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int kseed_setup(const unsigned char *key, int keylen, int num_rounds, kseed_key *skey);

/**
  Encrypts a block of text with SEED
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int kseed_ecb_encrypt(const unsigned char *pt, unsigned char *ct, kseed_key *skey);

/**
  Decrypts a block of text with SEED
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled 
  @return CRYPT_OK if successful
*/
int kseed_ecb_decrypt(const unsigned char *ct, unsigned char *pt, kseed_key *skey);

// Add by Zhang Luduo, 2014-09-28
int kseed_crypt_cbc( kseed_key *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );

// Add by Zhang Luduo, 2014-09-28
int kseed_crypt_cfb128( kseed_key *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo, 2014-09-28
int kseed_crypt_ofb( kseed_key *ctx,
                       int length,
                       int *iv_off,      //(updated after use)
                       unsigned char iv[16], //(updated after use)
                       const unsigned char *input,
                       unsigned char *output );

// Add by Zhang Luduo, 2014-09-28
int kseed_crypt_ctr( kseed_key *ctx,
                       int length,
                       int *nc_off,
                       unsigned char nonce_counter[16],
                       const unsigned char *input,
                       unsigned char *output );

#endif // !defined(AFX_SEED_H__1EA19BDD_FE81_4F6A_8F48_1A262265F86B__INCLUDED_)
