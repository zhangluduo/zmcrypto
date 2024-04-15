
#if !defined _SERPENT_H
#define _SERPENT_H

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

struct serpent_key {
      ulong32 l_key[140];
};

#define POLARSSL_ERR_SERPENT_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define POLARSSL_ERR_SERPENT_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

#define SERPENT_ENCRYPT     1
#define SERPENT_DECRYPT     0

int serpent_setup(const unsigned char *key, int key_len, int num_rounds, serpent_key *skey);
int serpent_ecb_encrypt(const unsigned char *pt, unsigned char *ct, serpent_key *skey);
int serpent_ecb_decrypt(const unsigned char *ct, unsigned char *pt, serpent_key *skey);
void serpent_done(serpent_key *skey);

// Add by Zhang Luduo(http://www.ZhangLuduo.com/)
// 2014-11-13
int serpent_crypt_cbc( serpent_key *ctx, int mode, int length, unsigned char iv[16], 
	const unsigned char *input, unsigned char *output );

// Add by Zhang Luduo(http://www.ZhangLuduo.com/)
// 2014-11-13
int serpent_crypt_cfb128( serpent_key *ctx, int mode, int length, int *iv_off,
	unsigned char iv[16], const unsigned char *input, unsigned char *output );

// Add by Zhang Luduo(http://www.ZhangLuduo.com/)
// 2014-11-14
int serpent_crypt_ofb( serpent_key *ctx, int length, int *iv_off,
	unsigned char iv[16], const unsigned char *input, unsigned char *output );

// Add by Zhang Luduo(http://www.ZhangLuduo.com/)
// 2014-11-14
int serpent_crypt_ctr( serpent_key *ctx, int length, int *nc_off, unsigned char nonce_counter[16], 
	unsigned char stream_block[16], const unsigned char *input, unsigned char *output );

#endif // _SERPENT_H