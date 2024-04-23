/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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

#ifndef GMSSL_SM2BN_H
#define GMSSL_SM2BN_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Big Endian R/W */

#define GETU16(p) \
	((uint16_t)(p)[0] <<  8 | \
	 (uint16_t)(p)[1])

#define GETU32(p) \
	((uint32_t)(p)[0] << 24 | \
	 (uint32_t)(p)[1] << 16 | \
	 (uint32_t)(p)[2] <<  8 | \
	 (uint32_t)(p)[3])

#define GETU64(p) \
	((uint64_t)(p)[0] << 56 | \
	 (uint64_t)(p)[1] << 48 | \
	 (uint64_t)(p)[2] << 40 | \
	 (uint64_t)(p)[3] << 32 | \
	 (uint64_t)(p)[4] << 24 | \
	 (uint64_t)(p)[5] << 16 | \
	 (uint64_t)(p)[6] <<  8 | \
	 (uint64_t)(p)[7])

#define PUTU16(p,V) \
	((p)[0] = (uint8_t)((V) >> 8), \
	 (p)[1] = (uint8_t)(V))

#define PUTU32(p,V) \
	((p)[0] = (uint8_t)((V) >> 24), \
	 (p)[1] = (uint8_t)((V) >> 16), \
	 (p)[2] = (uint8_t)((V) >>  8), \
	 (p)[3] = (uint8_t)(V))

#define PUTU64(p,V) \
	((p)[0] = (uint8_t)((V) >> 56), \
	 (p)[1] = (uint8_t)((V) >> 48), \
	 (p)[2] = (uint8_t)((V) >> 40), \
	 (p)[3] = (uint8_t)((V) >> 32), \
	 (p)[4] = (uint8_t)((V) >> 24), \
	 (p)[5] = (uint8_t)((V) >> 16), \
	 (p)[6] = (uint8_t)((V) >>  8), \
	 (p)[7] = (uint8_t)(V))

/* Little Endian R/W */

#define GETU16_LE(p)	(*(const uint16_t *)(p))
#define GETU32_LE(p)	(*(const uint32_t *)(p))
#define GETU64_LE(p)	(*(const uint64_t *)(p))

#define PUTU16_LE(p,V)	*(uint16_t *)(p) = (V)
#define PUTU32_LE(p,V)	*(uint32_t *)(p) = (V)
#define PUTU64_LE(p,V)	*(uint64_t *)(p) = (V)

/* Rotate */

#define ROL32(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#define ROL64(a,n)	(((a)<<(n))|((a)>>(64-(n))))

#define ROR32(a,n)	ROL32((a),32-(n))
#define ROR64(a,n)	ROL64(a,64-n)

typedef uint64_t SM2_BN[8];

#if !defined _SM2_POINT
#define _SM2_POINT
	typedef struct {
		uint8_t x[32];
		uint8_t y[32];
	} SM2_POINT;
#endif

// GF(p)
typedef SM2_BN SM2_Fp;

// GF(n)
typedef SM2_BN SM2_Fn;

typedef struct {
	SM2_BN X;
	SM2_BN Y;
	SM2_BN Z;
} SM2_JACOBIAN_POINT;

#define sm2_bn_init(r) memset((r),0,sizeof(SM2_BN))
#define sm2_bn_set_zero(r) memset((r),0,sizeof(SM2_BN))
#define sm2_bn_set_one(r) sm2_bn_set_word((r),1)
#define sm2_bn_copy(r,a) memcpy((r),(a),sizeof(SM2_BN))
#define sm2_bn_clean(r) memset((r),0,sizeof(SM2_BN))

#define sm2_fp_init(r)		sm2_bn_init(r)
#define sm2_fp_set_zero(r)	sm2_bn_set_zero(r)
#define sm2_fp_set_one(r)	sm2_bn_set_one(r)
#define sm2_fp_copy(r,a)	sm2_bn_copy(r,a)
#define sm2_fp_clean(r)		sm2_bn_clean(r)

#define sm2_fn_init(r)		sm2_bn_init(r)
#define sm2_fn_set_zero(r)	sm2_bn_set_zero(r)
#define sm2_fn_set_one(r)	sm2_bn_set_one(r)
#define sm2_fn_copy(r,a)	sm2_bn_copy(r,a)
#define sm2_fn_clean(r)		sm2_bn_clean(r)

#define sm2_jacobian_point_set_infinity(R) sm2_jacobian_point_init(R)
#define sm2_jacobian_point_copy(R, P) memcpy((R), (P), sizeof(SM2_JACOBIAN_POINT))

extern const SM2_BN SM2_P;
// extern const SM2_BN SM2_A;
extern const SM2_BN SM2_B;
extern const SM2_BN SM2_N;
extern const SM2_BN SM2_ONE;
extern const SM2_BN SM2_TWO;
extern const SM2_BN SM2_THREE;
extern const SM2_BN SM2_U_PLUS_ONE;
extern const SM2_JACOBIAN_POINT *SM2_G;

int hexchar2int(char c);
int hex2bin(const char *in, size_t inlen, uint8_t *out);

int  sm2_bn_check(const SM2_BN a);
int  sm2_bn_is_zero(const SM2_BN a);
int  sm2_bn_is_one(const SM2_BN a);
void sm2_bn_to_bytes(const SM2_BN a, uint8_t out[32]);
void sm2_bn_from_bytes(SM2_BN r, const uint8_t in[32]);
void sm2_bn_to_hex(const SM2_BN a, char hex[64]);
int  sm2_bn_from_hex(SM2_BN r, const char hex[64]);
void sm2_bn_to_bits(const SM2_BN a, char bits[256]);
int  sm2_bn_cmp(const SM2_BN a, const SM2_BN b);
int  sm2_bn_equ_hex(const SM2_BN a, const char *hex);
int  sm2_bn_is_odd(const SM2_BN a);
void sm2_bn_set_word(SM2_BN r, uint32_t a);
void sm2_bn_add(SM2_BN r, const SM2_BN a, const SM2_BN b);
void sm2_bn_sub(SM2_BN ret, const SM2_BN a, const SM2_BN b);
void sm2_bn_rand_range(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, SM2_BN r, const SM2_BN range);
void sm2_fp_add(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_sub(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_dbl(SM2_Fp r, const SM2_Fp a);
void sm2_fp_tri(SM2_Fp r, const SM2_Fp a);
void sm2_fp_div2(SM2_Fp r, const SM2_Fp a);
void sm2_fp_neg(SM2_Fp r, const SM2_Fp a);
void sm2_fp_mul(SM2_Fp r, const SM2_Fp a, const SM2_Fp b);
void sm2_fp_sqr(SM2_Fp r, const SM2_Fp a);
void sm2_fp_exp(SM2_Fp r, const SM2_Fp a, const SM2_Fp e);
void sm2_fp_inv(SM2_Fp r, const SM2_Fp a);
void sm2_fn_add(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_sub(SM2_Fn r, const SM2_Fn a, const SM2_Fn b);
void sm2_fn_neg(SM2_Fn r, const SM2_Fn a);
void sm2_fn_mul(SM2_BN r, const SM2_BN a, const SM2_BN b);
void sm2_fn_sqr(SM2_BN r, const SM2_BN a);
void sm2_fn_exp(SM2_BN r, const SM2_BN a, const SM2_BN e);
void sm2_fn_inv(SM2_BN r, const SM2_BN a);
void sm2_fn_rand(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, SM2_BN r);

int  sm2_bn288_cmp(const uint64_t a[9], const uint64_t b[9]); /* bn288 only used in barrett reduction */
void sm2_bn288_add(uint64_t r[9], const uint64_t a[9], const uint64_t b[9]);
void sm2_bn288_sub(uint64_t ret[9], const uint64_t a[9], const uint64_t b[9]);

void sm2_jacobian_point_init(SM2_JACOBIAN_POINT *R);
int  sm2_jacobian_point_is_at_infinity(const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_set_xy(SM2_JACOBIAN_POINT *R, const SM2_BN x, const SM2_BN y);
void sm2_jacobian_point_get_xy(const SM2_JACOBIAN_POINT *P, SM2_BN x, SM2_BN y);
int  sm2_jacobian_point_is_on_curve(const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_neg(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_dbl(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_add(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q);
void sm2_jacobian_point_sub(SM2_JACOBIAN_POINT *R, const SM2_JACOBIAN_POINT *P, const SM2_JACOBIAN_POINT *Q);
void sm2_jacobian_point_mul(SM2_JACOBIAN_POINT *R, const SM2_BN k, const SM2_JACOBIAN_POINT *P);
void sm2_jacobian_point_to_bytes(const SM2_JACOBIAN_POINT *P, uint8_t out[64]);
void sm2_jacobian_point_from_bytes(SM2_JACOBIAN_POINT *P, const uint8_t in[64]);
void sm2_jacobian_point_mul_generator(SM2_JACOBIAN_POINT *R, const SM2_BN k);
void sm2_jacobian_point_mul_sum(SM2_JACOBIAN_POINT *R, const SM2_BN t, const SM2_JACOBIAN_POINT *P, const SM2_BN s);/* R = t * P + s * G */
void sm2_jacobian_point_from_hex(SM2_JACOBIAN_POINT *P, const char hex[64 * 2]);
int  sm2_jacobian_point_equ_hex(const SM2_JACOBIAN_POINT *P, const char hex[128]);

int  sm2_point_is_on_curve(const SM2_POINT *P);
int  sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y);
int  sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32]);
int  sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P);
int  sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32]);
int  sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32]);

#ifdef __cplusplus
}
#endif
#endif
