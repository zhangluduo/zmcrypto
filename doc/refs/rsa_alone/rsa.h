/**
 * \file rsa.h
 *
 * \brief The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
Modifier: Zhang Luduo (zhangluduo@qq.com)
Date: 6/2022
NOTE: I hope this source code can minimize dependencies
*/

/* PolarSSL 1.3.9 */
#ifndef POLARSSL_RSA_H
#define POLARSSL_RSA_H

#include <stdint.h>
#include <stddef.h>
#include "rsabn.h"

/*
 * RSA Error codes
 */

#define POLARSSL_ERR_RSA_SUCCESSED                          0x00
#define POLARSSL_ERR_RSA_BAD_INPUT_DATA                    -0x4080  /**< Bad input parameters to function. */
#define POLARSSL_ERR_RSA_INVALID_PADDING                   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define POLARSSL_ERR_RSA_KEY_GEN_FAILED                    -0x4180  /**< Something failed during generation of a key. */
#define POLARSSL_ERR_RSA_KEY_CHECK_FAILED                  -0x4200  /**< Key failed to pass the libraries validity check. */
#define POLARSSL_ERR_RSA_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */
#define POLARSSL_ERR_RSA_PRIVATE_FAILED                    -0x4300  /**< The private key operation failed. */
#define POLARSSL_ERR_RSA_VERIFY_FAILED                     -0x4380  /**< The PKCS#1 verification failed. */
#define POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400  /**< The output buffer for decryption is not large enough. */
#define POLARSSL_ERR_RSA_RNG_FAILED                        -0x4480  /**< The random generator failed to generate non-zeros. */

/*
 * RSA constants
 */
#define RSA_PUBLIC      0
#define RSA_PRIVATE     1

#define RSA_PKCS_V15    0
#define RSA_PKCS_V21    1

#define RSA_SIGN        1
#define RSA_CRYPT       2

#define POLARSSL_MD_MAX_SIZE         64  /* longest known is SHA512 */

/*
 * The above constants may be used even if the RSA module is compile out,
 * eg for alternative (PKCS#11) RSA implemenations in the PK layers.
 */
#define POLARSSL_RSA_C
#if defined(POLARSSL_RSA_C)

#ifdef __cplusplus
extern "C" {
#endif

namespace polarssl{

/*
 * Digest algorithms
 */

#define OID_DIGEST_MD2    "\x2a\x86\x48\x86\xf7\x0d\x02\x02"
#define OID_DIGEST_MD4    "\x2a\x86\x48\x86\xf7\x0d\x02\x04"
#define OID_DIGEST_MD5    "\x2a\x86\x48\x86\xf7\x0d\x02\x05"
#define OID_DIGEST_SHA1   "\x2b\x0e\x03\x02\x1a"
#define OID_DIGEST_SHA256 "\x60\x86\x48\x01\x65\x03\x04\x02\x01"
#define OID_DIGEST_SHA384 "\x60\x86\x48\x01\x65\x03\x04\x02\x02"
#define OID_DIGEST_SHA512 "\x60\x86\x48\x01\x65\x03\x04\x02\x03"

#define OID_SIZE_MD2    (sizeof(OID_DIGEST_MD2   ) - 1)
#define OID_SIZE_MD4    (sizeof(OID_DIGEST_MD4   ) - 1)
#define OID_SIZE_MD5    (sizeof(OID_DIGEST_MD5   ) - 1)
#define OID_SIZE_SHA1   (sizeof(OID_DIGEST_SHA1  ) - 1)
#define OID_SIZE_SHA256 (sizeof(OID_DIGEST_SHA256) - 1)
#define OID_SIZE_SHA384 (sizeof(OID_DIGEST_SHA384) - 1)
#define OID_SIZE_SHA512 (sizeof(OID_DIGEST_SHA512) - 1)

/*Object ID string*/
#define SOID_DIGEST_MD2    "1.2.840.113549.2.2"
#define SOID_DIGEST_MD4    "1.2.840.113549.2.4"
#define SOID_DIGEST_MD5    "1.2.840.113549.2.5"
#define SOID_DIGEST_SHA1   "1.3.14.3.2.26"
#define SOID_DIGEST_SHA256 "2.16.840.1.101.3.4.2.1"
#define SOID_DIGEST_SHA384 "2.16.840.1.101.3.4.2.2"
#define SOID_DIGEST_SHA512 "2.16.840.1.101.3.4.2.3"

#define DIGEST_SIZE_MD2    16
#define DIGEST_SIZE_MD4    16
#define DIGEST_SIZE_MD5    16
#define DIGEST_SIZE_SHA1   20
#define DIGEST_SIZE_SHA256 32
#define DIGEST_SIZE_SHA384 48
#define DIGEST_SIZE_SHA512 64

typedef enum
{
    E_RSA_DIGEST_MD2    = 0,
    E_RSA_DIGEST_MD4    = 1,
    E_RSA_DIGEST_MD5    = 2,
    E_RSA_DIGEST_SHA1   = 3,
    E_RSA_DIGEST_SHA256 = 4,
    E_RSA_DIGEST_SHA384 = 5,
    E_RSA_DIGEST_SHA512 = 6,
} rsa_digest_type;

typedef struct 
{
    void*    (*digest_create)();
    void     (*digest_free  )(void* ctx);
    uint32_t (*digest_size  )();
    void     (*digest_init  )(void* ctx);
    void     (*digest_starts)(void* ctx);
    void     (*digest_update)(void* ctx, unsigned char* data, uint32_t len);
    void     (*digest_finish)(void* ctx, unsigned char* output);
    rsa_digest_type digest_type;
} rsa_digest_fn;

typedef struct 
{
    rsa_digest_fn digest_fn;
    void* digest_ctx;
} rsa_digest_context;

/**
 * \brief          RSA context structure
 */

typedef struct
{
    size_t len;                 /*!<  size(N) in chars  */

    mpi N;                      /*!<  public modulus    */
    mpi E;                      /*!<  public exponent   */

    mpi D;                      /*!<  private exponent  */
    mpi P;                      /*!<  1st prime factor  */
    mpi Q;                      /*!<  2nd prime factor  */
    mpi DP;                     /*!<  D % (P - 1)       */
    mpi DQ;                     /*!<  D % (Q - 1)       */
    mpi QP;                     /*!<  1 / (Q % P)       */

    mpi RN;                     /*!<  cached R^2 mod N  */
    mpi RP;                     /*!<  cached R^2 mod P  */
    mpi RQ;                     /*!<  cached R^2 mod Q  */

    mpi Vi;                     /*!<  cached blinding value     */
    mpi Vf;                     /*!<  cached un-blinding value  */
} rsa_key;

/**
 * The following functions return 0 (POLARSSL_ERR_RSA_SUCCESSED) on success 
 * and <0 (POLARSSL_ERR_RSA_XXX) on failure.
 */

/**
 * @brief 
 * 
 * @param key             an RSA key
 * @param f_rng           RNG function
 * @param p_rng           RNG parameter
 * @param digest_ctx      digest function context
 * @param digest_fn       digest function
 * @param input           buffer holding the data to be encrypted/decrypted/signed
 * @param ilen            contains the plaintext/ciphertext/signature length
 * @param output          buffer that will hold the plaintext/ciphertext/signature
 * @param olen            contains the plaintext/ciphertext/signature length
 * @param label           buffer holding the custom label to use
 * @param llen            contains the label length
 * @param nbits           bits of public modulus
 * @param exponent        public exponent
 * @param md              buffer holding the message digest
 * @param sig             buffer holding the signature
 * @param mgf1            digest function, that use MGF function
 * @param klen            size of public modulus
 * 
 * \note                  -
 * \note                  -
 * \return                0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */

void rsa_init (rsa_key *key);
void rsa_free (rsa_key *key);
int  rsa_gen_key (rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, unsigned int nbits, int exponent);
int  rsa_check_pubkey (const rsa_key *key);
int  rsa_check_privkey (const rsa_key *key);
void rsa_digest_create(rsa_digest_context* digest_ctx, rsa_digest_fn* digest_fn);
void rsa_digest_free(rsa_digest_context* ctx);

int  rsa_rsaes_pkcs1_v15_encrypt (rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, 
        size_t ilen, const unsigned char *input, unsigned char *output);
int  rsa_rsaes_pkcs1_v15_decrypt (rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, 
        const unsigned char *input, unsigned char *output, size_t* olen);

int  rsa_rsaes_oaep_encrypt (rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, 
        rsa_digest_fn* mgf1, const unsigned char *label, size_t label_len, const unsigned char *input, size_t ilen, unsigned char *output);
int  rsa_rsaes_oaep_decrypt (rsa_key *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, 
        rsa_digest_fn* mgf1, const unsigned char *label, size_t llen, const unsigned char *input, unsigned char *output, size_t *olen);

void rsa_rsassa_pkcs1_v15_sign_start(rsa_digest_context* ctx);
void rsa_rsassa_pkcs1_v15_sign_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen);
int  rsa_rsassa_pkcs1_v15_sign_finish(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* sig);
int  rsa_rsassa_pkcs1_v15_sign_oneshot(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* md, unsigned char* sig);

void rsa_rsassa_pkcs1_v15_verify_start(rsa_digest_context* ctx);
void rsa_rsassa_pkcs1_v15_verify_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen);
int  rsa_rsassa_pkcs1_v15_verify_finish(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* sig);
int  rsa_rsassa_pkcs1_v15_verify_oneshot(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* md, unsigned char* sig);

void rsa_rsassa_pss_sign_start(rsa_digest_context* ctx);
void rsa_rsassa_pss_sign_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen);
int  rsa_rsassa_pss_sign_finish(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* sig);
int  rsa_rsassa_pss_sign_oneshot(rsa_key* key, rsa_digest_fn* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* md, unsigned char* sig);

void rsa_rsassa_pss_verify_start(rsa_digest_context* ctx);
void rsa_rsassa_pss_verify_update(rsa_digest_context* ctx, const unsigned char* data, unsigned int dlen);
int  rsa_rsassa_pss_verify_finish(rsa_key* key, rsa_digest_context* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* sig);
int  rsa_rsassa_pss_verify_oneshot(rsa_key* key, rsa_digest_fn* digest, int (*f_rng)(void *, unsigned char *, size_t), 
        void *p_rng, unsigned char* md, unsigned char* sig);

/**
 * RSA helper functions.
 * 
 * The following function returns the length, 
 * but does not return an error code.
 * returns may be 0.
 */
unsigned int rsa_helper_rsassa_pkcs1_v15_fixed_len(unsigned int klen);
unsigned int rsa_helper_rsassa_pss_fixed_len(unsigned int klen);
unsigned int rsa_helper_rsaes_pkcs1_v15_max_pt_len(unsigned int klen);
unsigned int rsa_helper_rsaes_pkcs1_v15_fixed_ct_len(unsigned int klen);
unsigned int rsa_helper_rsaes_oaep_max_pt_len(unsigned int klen, unsigned int mgf_digest_size);
unsigned int rsa_helper_rsaes_oaep_fixed_ct_len(unsigned int klen);

int test();
} /* namespace polarssl */

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_RSA_C */

#endif /* rsa.h */
