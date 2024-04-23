/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * This file has been modified by Zhang Luduo(zhangluduo@qq.com), 
 * I want it to reduce external dependencies.
 * __Zhang Luduo, 2022-10-24
*/

#ifndef GMSSL_SM2_H
#define GMSSL_SM2_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_DEFAULT_ID           "1234567812345678"
#define SM2_DEFAULT_ID_LENGTH    (sizeof(SM2_DEFAULT_ID) - 1)  // LENGTH for string and SIZE for bytes
#define SM2_DEFAULT_ID_BITS      (SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_MAX_ID_BITS          65535
#define SM2_MAX_ID_LENGTH        (SM2_MAX_ID_BITS/8)

#define SM2_MIN_PLAINTEXT_SIZE    1
#define SM2_MAX_PLAINTEXT_SIZE    255

typedef enum 
{
    e_sm2_c1c2c3 = 0,
    e_sm2_c1c3c2 = 1,
} SM2_CIPHER_FORMAT;

typedef struct 
{
    void* (*create)();
    void  (*free)(void* ctx);
    void  (*init)(void* ctx);
    void  (*starts)(void* ctx);
    void  (*update)(void* ctx, unsigned char* data, uint32_t len);
    void  (*finish)(void* ctx, unsigned char* output);
} SM3_FN;

#if !defined _SM2_POINT
#define _SM2_POINT
    typedef struct {
        uint8_t x[32];
        uint8_t y[32];
    } SM2_POINT;
#endif

typedef struct {
    SM2_POINT point;             /* C1 */
    uint8_t digest[32];          /* C3 */
    uint8_t ciphertext_size;     /* C2 */
    uint8_t ciphertext[SM2_MAX_PLAINTEXT_SIZE];
} SM2_CIPHERTEXT;

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
} SM2_SIGNATURE;

typedef struct {
    SM2_POINT public_key;
    uint8_t private_key[32];
} SM2_KEY;

typedef struct {
    void* sm3_ctx;
    SM2_KEY key;
    SM3_FN sm3_fn;
} SM2_SIGN_CTX;

/* public interface 
*/

void sm2_init_key(SM2_KEY *key);
void sm2_init_sign_ctx(SM2_SIGN_CTX *ctx);
void sm2_init_signature(SM2_SIGNATURE *sig);
void sm2_init_ciphertext(SM2_CIPHERTEXT *text);

int sm2_key_generate(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, SM2_KEY *key);
int sm2_key_decompress(SM2_KEY *key, int compress_flag/*0x02 | 0x03*/);

int sm2_sign_init(SM2_SIGN_CTX *ctx, SM2_KEY *key, SM3_FN fn, char *id, size_t idlen);
int sm2_sign_update(SM2_SIGN_CTX *ctx, uint8_t *data, size_t dlen);
int sm2_sign_finish(SM2_SIGN_CTX *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, SM2_SIGNATURE* signature);

int sm2_verify_init(SM2_SIGN_CTX *ctx, SM2_KEY *key, SM3_FN fn, char *id, size_t idlen);
int sm2_verify_update(SM2_SIGN_CTX *ctx, uint8_t *data, size_t dlen);
int sm2_verify_finish(SM2_SIGN_CTX *ctx, SM2_SIGNATURE* signature);

int sm2_encrypt(SM2_KEY *key, SM3_FN fn, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, uint8_t *in, size_t inlen, SM2_CIPHERTEXT* output);
int sm2_decrypt(SM2_KEY *key, SM3_FN fn, SM2_CIPHERTEXT* input, uint8_t *out, size_t *outlen);

/* public interface 
Use the result to encode or decode DER 
*/

int  sm2_encode_signagure_to_der(SM2_SIGNATURE* in, unsigned char** out, uint32_t* olen);
void sm2_encode_signagure_to_der_free(unsigned char** out);
int  sm2_decode_signagure_from_der(unsigned char* in, uint32_t ilen, SM2_SIGNATURE* out);
int  sm2_encode_cipher_to_der(SM2_CIPHERTEXT* in, SM2_CIPHER_FORMAT format, unsigned char** out, uint32_t* olen);
void sm2_encode_cipher_to_der_free(unsigned char** out);
int  sm2_decode_cipher_from_der(unsigned char* in, uint32_t ilen, SM2_CIPHER_FORMAT format, SM2_CIPHERTEXT* out);

#ifdef __cplusplus
}
#endif
#endif
