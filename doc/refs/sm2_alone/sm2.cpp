
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

#include "sm2.h"
#include "sm2bn.h"

namespace ns_sm2_private
{
    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
    int sm2_compute_z(SM3_FN fn, SM2_POINT *pub, char *id, size_t idlen, uint8_t z[32])
    {
        uint8_t zin[32 * 4] = 
        {
            /* a of sm2p256v1 */
            0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
            /* b of sm2p256v1 */
            0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7, 
            0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
            /* xa of sm2p256v1 */
            0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94, 
            0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
            /* xb of sm2p256v1 */
            0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53, 
            0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
        };

        if (!z || !pub || !id) {
            return -1;
        }

        uint8_t idbits[2];
        idbits[0] = (uint8_t)(idlen >> 5);
        idbits[1] = (uint8_t)(idlen << 3);

        void* ctx = fn.create();
        fn.init(ctx);
        fn.starts(ctx);
        fn.update(ctx, idbits, 2);
        fn.update(ctx, (uint8_t *)id, idlen);
        fn.update(ctx, zin, 32 * 4);
        fn.update(ctx, (unsigned char*)pub->x, 32);
        fn.update(ctx, (unsigned char*)pub->y, 32);
        fn.finish(ctx, z);
        fn.free(ctx);
        return 1;
    }

    int sm2_do_sign(SM2_KEY *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, uint8_t dgst[32], SM2_SIGNATURE *sig)
    {
        SM2_JACOBIAN_POINT _P, *P = &_P;
        SM2_BN d;
        SM2_BN e;
        SM2_BN k;
        SM2_BN x;
        SM2_BN r;
        SM2_BN s;

        sm2_bn_from_bytes(d, key->private_key);

        // e = H(M)
        sm2_bn_from_bytes(e, dgst);	//print_bn("e", e);

    retry:
        // rand k in [1, n - 1]
        do {
            sm2_fn_rand(f_rng, p_rng, k);
        } while (sm2_bn_is_zero(k));

        // (x, y) = kG
        sm2_jacobian_point_mul_generator(P, k);
        sm2_jacobian_point_get_xy(P, x, NULL);

        // r = e + x (mod n)
        sm2_fn_add(r, e, x);		//print_bn("r = e + x (mod n)", r);

        /* if r == 0 or r + k == n re-generate k */
        if (sm2_bn_is_zero(r)) {
            goto retry;
        }
        sm2_bn_add(x, r, k);
        if (sm2_bn_cmp(x, SM2_N) == 0) {
            goto retry;
        }

        /* s = ((1 + d)^-1 * (k - r * d)) mod n */

        sm2_fn_mul(e, r, d);        //print_bn("r*d", e);
        sm2_fn_sub(k, k, e);        //print_bn("k-r*d", k);
        sm2_fn_add(e, SM2_ONE, d);  //print_bn("1 +d", e);
        sm2_fn_inv(e, e);           //print_bn("(1+d)^-1", e);
        sm2_fn_mul(s, e, k);        //print_bn("s = ((1 + d)^-1 * (k - r * d)) mod n", s);

        sm2_bn_clean(d);
        sm2_bn_clean(k);
        sm2_bn_to_bytes(r, sig->r);	//print_bn("r", r);
        sm2_bn_to_bytes(s, sig->s);	//print_bn("s", s);

        sm2_bn_clean(d);
        sm2_bn_clean(k);
        return 1;
    }

    int sm2_sign(SM2_KEY *key, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, uint8_t dgst[32], SM2_SIGNATURE* signature)
    {
        uint8_t *p;

        if (!key || !dgst || !signature) {
            return -1;
        }

        if (sm2_do_sign(key, f_rng, p_rng, dgst, signature) != 1) {
            return -1;
        }

        return 1;
    }

    int sm2_do_verify(SM2_KEY *key, uint8_t dgst[32], SM2_SIGNATURE *sig)
    {
        SM2_JACOBIAN_POINT _P, *P = &_P;
        SM2_JACOBIAN_POINT _R, *R = &_R;
        SM2_BN r;
        SM2_BN s;
        SM2_BN e;
        SM2_BN x;
        SM2_BN t;

        // parse signature values
        sm2_bn_from_bytes(r, sig->r);	//print_bn("r", r);
        sm2_bn_from_bytes(s, sig->s);	//print_bn("s", s);
        if (sm2_bn_is_zero(r) == 1
            || sm2_bn_cmp(r, SM2_N) >= 0
            || sm2_bn_is_zero(s) == 1
            || sm2_bn_cmp(s, SM2_N) >= 0) {
            return -1;
        }

        // parse public key
        sm2_jacobian_point_from_bytes(P, (uint8_t *)&key->public_key);

        // t = r + s (mod n)
        // check t != 0
        sm2_fn_add(t, r, s);		//print_bn("t = r + s (mod n)", t);
        if (sm2_bn_is_zero(t)) {
            return -1;
        }

        // Q = s * G + t * P
        sm2_jacobian_point_mul_sum(R, t, P, s);
        sm2_jacobian_point_get_xy(R, x, NULL);

        // e  = H(M)
        // r' = e + x (mod n)
        sm2_bn_from_bytes(e, dgst);	//print_bn("e = H(M)", e);
        sm2_fn_add(e, e, x);		//print_bn("e + x (mod n)", e);

        // check if r == r'
        if (sm2_bn_cmp(e, r) == 0) {
            return 1;
        } else {
            return 0;
        }
    }

    int sm2_verify(SM2_KEY *key, uint8_t dgst[32], SM2_SIGNATURE* signature)
    {
        int ret;
        uint8_t *p;
        size_t len;

        if (!key || !dgst || !signature) {
            return -1;
        }

        if ((ret = sm2_do_verify(key, dgst, signature)) != 1) {
            if (ret <= 0){
                return ret;
            }
        }
        return 1;
    }

    int sm2_kdf(SM2_KEY* sm2_key, SM3_FN fn, uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
    {
        uint8_t counter_be[4];
        uint8_t dgst[32];
        uint32_t counter = 1;
        size_t len;

        /*
        size_t i; fprintf(stderr, "kdf input : ");
        for (i = 0; i < inlen; i++) fprintf(stderr, "%02x", in[i]); fprintf(stderr, "\n");
        */

        void* sm3_ctx = fn.create();
        while (outlen) {
            PUTU32(counter_be, counter);
            counter++;

            fn.init(sm3_ctx);
            fn.starts(sm3_ctx);
            fn.update(sm3_ctx, (uint8_t*) in, inlen);
            fn.update(sm3_ctx, counter_be, sizeof(counter_be));
            fn.finish(sm3_ctx, dgst);

            len = outlen < 32/* SM3_DIGEST_SIZE */ ? outlen : 32/* SM3_DIGEST_SIZE */;
            memcpy(out, dgst, len);
            out += len;
            outlen -= len;
        }

        fn.free(sm3_ctx);
        sm3_ctx = NULL;

        memset(dgst, 0, sizeof(dgst));
        return 1;
    }

    int sm2_do_encrypt(SM2_KEY *key, SM3_FN fn, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
    {
        SM2_BN k;
        SM2_JACOBIAN_POINT _P, *P = &_P;

        uint8_t buf[64];
        int i;

        // rand k in [1, n - 1]
        do {
            sm2_bn_rand_range(f_rng, p_rng, k, SM2_N);
        } while (sm2_bn_is_zero(k));

        // C1 = k * G = (x1, y1)
        sm2_jacobian_point_mul_generator(P, k);
        sm2_jacobian_point_to_bytes(P, (uint8_t *)&out->point);

        // Q = k * P = (x2, y2)
        sm2_jacobian_point_from_bytes(P, (uint8_t *)&key->public_key);
        sm2_jacobian_point_mul(P, k, P);
        sm2_jacobian_point_to_bytes(P, buf);

        // t = KDF(x2 || y2, klen)
        sm2_kdf(key, fn, buf, sizeof(buf), inlen, out->ciphertext);

        // C2 = M xor t
        for (i = 0; i < inlen; i++) {
            out->ciphertext[i] ^= in[i];
        }
        out->ciphertext_size = (uint32_t)inlen;

        // C3 = Hash(x2 || m || y2)
        void* sm3_ctx = fn.create();
        fn.init(sm3_ctx);
        fn.starts(sm3_ctx);
        fn.update(sm3_ctx, buf, 32);
        fn.update(sm3_ctx, (uint8_t*) in, inlen);
        fn.update(sm3_ctx, buf + 32, 32);
        fn.finish(sm3_ctx, out->digest);
        fn.free(sm3_ctx);
        sm3_ctx = NULL;

        return 1;
    }

    int sm2_do_decrypt(SM2_KEY *key, SM3_FN fn, SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen)
    {
        uint32_t inlen;
        SM2_BN d;
        SM2_JACOBIAN_POINT _P, *P = &_P;
        uint8_t buf[64];
        uint8_t digest[32];
        int i;

        // FIXME: check SM2_CIPHERTEXT format

        // check C1
        sm2_jacobian_point_from_bytes(P, (uint8_t *)&in->point);
        //point_print(stdout, P, 0, 2);

        /*
        if (!sm2_jacobian_point_is_on_curve(P)) {
            fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
            return -1;
        }
        */

        // d * C1 = (x2, y2)
        sm2_bn_from_bytes(d, key->private_key);
        sm2_jacobian_point_mul(P, d, P);
        sm2_bn_clean(d);
        sm2_jacobian_point_to_bytes(P, buf);

        // t = KDF(x2 || y2, klen)
        if ((inlen = in->ciphertext_size) <= 0) {
            fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
            return -1;
        }

        sm2_kdf(key, fn, buf, sizeof(buf), inlen, out);

        // M = C2 xor t
        for (i = 0; i < inlen; i++) {
            out[i] ^= in->ciphertext[i];
        }
        *outlen = inlen;

        // u = Hash(x2 || M || y2)
        void* sm3_ctx = fn.create();
        fn.init(sm3_ctx);
        fn.starts(sm3_ctx);
        fn.update(sm3_ctx, buf, 32);
        fn.update(sm3_ctx, out, inlen);
        fn.update(sm3_ctx, buf + 32, 32);
        fn.finish(sm3_ctx, digest);
        fn.free(sm3_ctx);
        sm3_ctx = NULL;

        // check if u == C3
        if (memcmp(in->digest, digest, sizeof(digest)) != 0) {
            fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
            return -1;
        }

        return 1;
    }
} /* ns_sm2_private */

void sm2_init_key(SM2_KEY *key) 
    { memset (key, 0, sizeof(SM2_KEY)); }

void sm2_init_sign_ctx(SM2_SIGN_CTX *ctx) 
    { memset (ctx, 0, sizeof(SM2_SIGN_CTX)); }

void sm2_init_signature(SM2_SIGNATURE *sig) 
    { memset (sig, 0, sizeof(SM2_SIGNATURE)); }

void sm2_init_ciphertext(SM2_CIPHERTEXT *text) 
    { memset (text, 0, sizeof(SM2_CIPHERTEXT)); }

int sm2_sign_init(SM2_SIGN_CTX *ctx, SM2_KEY *key, SM3_FN fn, char *id, size_t idlen)
{
    if (!ctx || !key) {
        return -1;
    }

    if (fn.create == NULL ||
        fn.free   == NULL ||
        fn.init   == NULL ||
        fn.starts == NULL ||
        fn.update == NULL ||
        fn.finish == NULL)
    {
        return -1;
    }

    ctx->key = *key;
    ctx->sm3_fn = fn;
    ctx->sm3_ctx = fn.create();
    fn.init(ctx->sm3_ctx);
    fn.starts(ctx->sm3_ctx);

    if (id) {
        uint8_t z[32];
        if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
            return -1;
        }
        ns_sm2_private::sm2_compute_z(fn, (SM2_POINT*)(&(key->public_key)), id, idlen, z);
        fn.update(ctx->sm3_ctx, z, sizeof(z));
    }
    return 1;
}

int sm2_sign_update(SM2_SIGN_CTX *ctx, uint8_t *data, size_t dlen)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->sm3_fn.create == NULL ||
        ctx->sm3_fn.free   == NULL ||
        ctx->sm3_fn.init   == NULL ||
        ctx->sm3_fn.starts == NULL ||
        ctx->sm3_fn.update == NULL ||
        ctx->sm3_fn.finish == NULL)
    {
        return -1;
    }

    if (data && dlen > 0) {
        ctx->sm3_fn.update(ctx->sm3_ctx, (unsigned char*)data, dlen);
    }
    return 1;
}

int sm2_sign_finish(SM2_SIGN_CTX *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, SM2_SIGNATURE* signature)
{
    int ret = 0;
    uint8_t dgst[32];

    if (!ctx) {
        return -1;
    }

    if (ctx->sm3_fn.create == NULL ||
        ctx->sm3_fn.free   == NULL ||
        ctx->sm3_fn.init   == NULL ||
        ctx->sm3_fn.starts == NULL ||
        ctx->sm3_fn.update == NULL ||
        ctx->sm3_fn.finish == NULL)
    {
        return -1;
    }

    ctx->sm3_fn.finish(ctx->sm3_ctx, dgst);

    if ((ret = ns_sm2_private::sm2_sign(&ctx->key, f_rng, p_rng, dgst, signature)) != 1) {
        /* error */
    }

    ctx->sm3_fn.free(ctx->sm3_ctx);
    ctx->sm3_ctx = NULL;

    if (ret <= 0)
        return ret;
    return 1;
}

int sm2_verify_init(SM2_SIGN_CTX *ctx, SM2_KEY *key, SM3_FN fn, char *id, size_t idlen)
{
    if (!ctx || !key) {
        return -1;
    }

    if (fn.create == NULL ||
        fn.free   == NULL ||
        fn.init   == NULL ||
        fn.starts == NULL ||
        fn.update == NULL ||
        fn.finish == NULL)
    {
        return -1;
    }

    ctx->key = *key;
    ctx->sm3_fn = fn;
    ctx->sm3_ctx = fn.create();
    fn.init(ctx->sm3_ctx);
    fn.starts(ctx->sm3_ctx);

    if (id) {
        uint8_t z[32];
        if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
            return -1;
        }
        ns_sm2_private::sm2_compute_z(fn, (SM2_POINT*)(&(key->public_key)), id, idlen, z);
        fn.update(ctx->sm3_ctx, z, sizeof(z));
    }
    return 1;
}

int sm2_verify_update(SM2_SIGN_CTX *ctx, uint8_t *data, size_t dlen)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->sm3_fn.create == NULL ||
        ctx->sm3_fn.free   == NULL ||
        ctx->sm3_fn.init   == NULL ||
        ctx->sm3_fn.starts == NULL ||
        ctx->sm3_fn.update == NULL ||
        ctx->sm3_fn.finish == NULL)
    {
        return -1;
    }

    if (data && dlen > 0) {
        ctx->sm3_fn.update(ctx->sm3_ctx, (unsigned char*)data, dlen);
    }
    return 1;
}

int sm2_verify_finish(SM2_SIGN_CTX *ctx, SM2_SIGNATURE* signature)
{
    int ret = 0;
    uint8_t dgst[32];

    if (!ctx) {
        return -1;
    }

    if (ctx->sm3_fn.create == NULL ||
        ctx->sm3_fn.free   == NULL ||
        ctx->sm3_fn.init   == NULL ||
        ctx->sm3_fn.starts == NULL ||
        ctx->sm3_fn.update == NULL ||
        ctx->sm3_fn.finish == NULL)
    {
        return -2;
    }

    ctx->sm3_fn.finish(ctx->sm3_ctx, dgst);

    if ((ret = ns_sm2_private::sm2_verify(&ctx->key, dgst, signature)) != 1) {
        /* error */
    }

    ctx->sm3_fn.free(ctx->sm3_ctx);
    ctx->sm3_ctx = NULL;

    if (ret <= 0)
        return ret;
    return 1;
}

int sm2_encrypt(SM2_KEY *key, SM3_FN fn, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, uint8_t *in, size_t inlen, SM2_CIPHERTEXT* output)
{
    if (!key || !in || !output) {
        return -1;
    }

    if (fn.create == NULL ||
        fn.free   == NULL ||
        fn.init   == NULL ||
        fn.starts == NULL ||
        fn.update == NULL ||
        fn.finish == NULL)
    {
        return -1;
    }

    if (inlen < SM2_MIN_PLAINTEXT_SIZE || inlen > SM2_MAX_PLAINTEXT_SIZE) {
        return -1;
    }
    if (ns_sm2_private::sm2_do_encrypt(key, fn, f_rng, p_rng, in, inlen, output) != 1) {
        return -1;
    }
    return 1;
}

int sm2_decrypt(SM2_KEY *key, SM3_FN fn, SM2_CIPHERTEXT* input, uint8_t *out, size_t *outlen)
{
    if (!key || !input || !out || !outlen) {
        return -1;
    }

    if (fn.create == NULL ||
        fn.free   == NULL ||
        fn.init   == NULL ||
        fn.starts == NULL ||
        fn.update == NULL ||
        fn.finish == NULL)
    {
        return -1;
    }

    if (ns_sm2_private::sm2_do_decrypt(key, fn, input, out, outlen) != 1) {
        return -1;
    }
    return 1;
}

int sm2_key_decompress(SM2_KEY *key, int compress_flag/*0x02 | 0x03*/)
{
    if (sm2_point_from_x(&(key->public_key), key->public_key.x, compress_flag) != 1) {
        return -1;
    }
    return 1;
}

int sm2_key_generate(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, SM2_KEY *key)
{
    SM2_BN x;
    SM2_BN y;
    SM2_JACOBIAN_POINT _P, *P = &_P;

    if (!key) {
        return -1;
    }
    memset(&(key->public_key), 0, sizeof(SM2_POINT));
    memset(key->private_key, 0, 32);

    do {
        sm2_bn_rand_range(f_rng, p_rng, x, SM2_N);
    } while (sm2_bn_is_zero(x));
    sm2_bn_to_bytes(x, key->private_key);

    sm2_jacobian_point_mul_generator(P, x);
    sm2_jacobian_point_get_xy(P, x, y);
    sm2_bn_to_bytes(x, key->public_key.x);
    sm2_bn_to_bytes(y, key->public_key.y);
    return 1;
}

int sm2_encode_signagure_to_der(SM2_SIGNATURE* in, unsigned char** out, uint32_t* olen)
{
    if (!out || !olen)
        return -1;

    int encode_len = 32 + 32;
    encode_len += ((in->r[0]) >> 7 == 1 ? 1 : 0);
    encode_len += ((in->s[0]) >> 7 == 1 ? 1 : 0);
    encode_len += 2; /* SEQUENCE(0x30), LENGTH */
    encode_len += 2; /* INTEGER(0x02), LENGTH */
    encode_len += 2; /* INTEGER(0x02), LENGTH */

    unsigned char* pout = new unsigned char[encode_len];
    memset(pout, 0, encode_len);

    int offset = 0;
    *(pout + offset) = 0x30;
    offset++;

    *(pout + offset) = (unsigned char)(encode_len - 2/* skip SEQUENCE(0x30), LENGTH */);
    offset++;

    *(pout + offset) = 0x02;
    offset++;

    *(pout + offset) = ((in->r[0]) >> 7 == 1 ? 0x21 : 0x20); 
    offset++;

    if ((in->r[0]) >> 7 == 1){
        *(pout + offset) = 0x00; /* Add 0 if the highest bit is 1 */
        offset++;
    }

    memcpy(pout + offset, in->r, 32); /* copy r data */
    offset += 32;

    *(pout + offset) = 0x02;
    offset++;

    *(pout + offset) = ((in->s[0]) >> 7 == 1 ? 0x21 : 0x20); 
    offset++;

    if ((in->s[0]) >> 7 == 1){
        *(pout + offset) = 0x00; /* Add 0 if the highest bit is 1 */
        offset++;
    }

    memcpy(pout + offset, in->s, 32); /* copy s data */
    offset += 32;

    *out = pout;
    *olen = encode_len;
    return 1;
}

void sm2_encode_signagure_to_der_free(unsigned char** out)
{
    if (out && *out){
        delete[] (*out);
        *out = NULL;
    }
}

int sm2_decode_signagure_from_der(unsigned char* in, uint32_t ilen, SM2_SIGNATURE* out)
{
    int ret = 0;
    if (ilen > 72){
        return -1;
    }

    unsigned char* pin = in;
    if (*pin++ != 0x30){
        return -2;
    }

    unsigned int payload = *pin++;
    if (payload > 70){
        return -3;
    }

    if (*pin++ != 0x02){
        return -4;
    }

    unsigned char rlen = *pin++;
    if (rlen != 0x20 && rlen != 0x21){
        return -5;
    }

    if (rlen == 0x21 && (*pin++) != 0x00){
        return -6;
    }
    
    memcpy(out->r,  pin, 32);
    pin += 32;

    if (*pin++ != 0x02){
        return -4;
    }

    unsigned char slen = *pin++;
    if (slen != 0x20 && slen != 0x21){
        return -5;
    }

    if (slen == 0x21 && (*pin++) != 0x00){
        return -6;
    }
    
    memcpy(out->s,  pin, 32);
    pin += 32;
    return 1;
}

int sm2_encode_cipher_to_der(SM2_CIPHERTEXT* in, SM2_CIPHER_FORMAT format, unsigned char** out, uint32_t* olen)
{
    if (!out || !olen){
        return -1;
    }

    /* point.x, point.y, digest, ciphertext_size*/
    int encode_len = 32 + 32 + 32 + in->ciphertext_size;
    encode_len += (in->point.x[0] >> 7 == 1 ? 1 : 0);
    encode_len += (in->point.y[0] >> 7 == 1 ? 1 : 0);
    encode_len += 2; /* SEQUENCE, LENGTH */
    encode_len += 2; /* INTEGER , LENGTH */
    encode_len += 2; /* INTEGER , LENGTH */
    encode_len += 2; /* OCTET STRING, LENGTH */
    encode_len += 2; /* OCTET STRING, LENGTH */

    unsigned char* pout = new unsigned char[encode_len];
    memset(pout, 0, encode_len);

    int offset = 0;
    *(pout + offset) = 0x30;
    offset++;

    *(pout + offset) = (unsigned char)(encode_len - 2/* not include SEQUENCE, LENGTH */);
    offset++;

    *(pout + offset) = 0x02;
    offset++;

    *(pout + offset) = (in->point.x[0] >> 7 == 1 ? 0x21 : 0x20); 
    offset++;

    if (in->point.x[0] >> 7 == 1){
        *(pout + offset) = 0x00; /* Add 0 */
        offset++;
    }

    memcpy(pout + offset, in->point.x, 32); /* copy point.x data */
    offset += 32;

    *(pout + offset) = 0x02;
    offset++;

    *(pout + offset) = (in->point.y[0] >> 7 == 1 ? 0x21 : 0x20); 
    offset++;

    if (in->point.y[0] >> 7 == 1){
        *(pout + offset) = 0x00; /* Add 0 */
        offset++;
    }

    memcpy(pout + offset, in->point.y, 32); /* copy point.y data */
    offset += 32;

    if (format == e_sm2_c1c2c3){
        *(pout + offset) = 0x04;
        offset++;

        *(pout + offset) = (unsigned char)(in->ciphertext_size);
        offset++;

        memcpy(pout + offset, in->ciphertext, in->ciphertext_size); /* copy cipher data */
        offset += in->ciphertext_size;

        *(pout + offset) = 0x04;
        offset++;

        *(pout + offset) = 0x20;
        offset++;

        memcpy(pout + offset, in->digest, 0x20); /* copy digest data */
        offset += 0x20;
    }
    else{
        *(pout + offset) = 0x04;
        offset++;

        *(pout + offset) = 0x20;
        offset++;

        memcpy(pout + offset, in->digest, 0x20); /* copy digest data */
        offset += 0x20;

        *(pout + offset) = 0x04;
        offset++;

        *(pout + offset) = (unsigned char)(in->ciphertext_size);
        offset++;

        memcpy(pout + offset, in->ciphertext, in->ciphertext_size); /* copy cipher data */
        offset += in->ciphertext_size;
    }

    *out = pout;
    *olen = encode_len;
    return 1;

fail:
    delete[] pout;
    pout = NULL;
    return -1;
}

void sm2_encode_cipher_to_der_free(unsigned char** out)
{
    if (out && *out){
        delete[] (*out);
        *out = NULL;
    }
}

int sm2_decode_cipher_from_der(unsigned char* in, uint32_t ilen, SM2_CIPHER_FORMAT format, SM2_CIPHERTEXT* out)
{
    int ret = 0;
    if (ilen < 117){
        return -1;
    }

    unsigned char* pin = in;
    if (*pin++ != 0x30){ return -2; }

    if (*pin++ != ilen - 2){ return -3; }

    if (*pin++ != 0x02){ return -4; }

    if (*pin != 0x20 && *pin != 0x21){ return -5; }

    if (*pin == 0x21 && *(pin + 1) != 0x00){ return -6; }

    memcpy(out->point.x, (*pin == 0x20 ? (pin + 1) : (pin + 2)), 0x20); /* copy point.x */
    pin += (*pin == 0x20 ? 1 : 2);
    pin += 0x20;
#if 0
    printf ("point.x: ");
    for (int i = 0; i < 32; i++){
        printf ("%02x ", out->point.x[i]);
    }   printf ("\n");
#endif
    if (*pin++ != 0x02){ return -7; }

    if (*pin != 0x20 && *pin != 0x21){ return -8; }

    if (*pin == 0x21 && *(pin + 1) != 0x00){ return -9; }

    memcpy(out->point.y, (*pin == 0x20 ? (pin + 1) : (pin + 2)), 0x20); /* copy point.y */
    pin += (*pin == 0x20 ? 1 : 2);
    pin += 0x20;
#if 0
    printf ("point.y: ");
    for (int i = 0; i < 32; i++){
        printf ("%02x ", out->point.y[i]);
    }   printf ("\n");
#endif
    /* xy,digest,cipher */
    if (format == e_sm2_c1c2c3){
        if (*pin++ != 0x04 || *pin++ != 0x20){ return -10; }
        memcpy(out->digest, pin, 0x20); /* copy digest */
        pin += 0x20;
#if 0
        printf ("digest: ");
        for (int i = 0; i < 32; i++){
            printf ("%02x ", out->digest[i]);
        }   printf ("\n");
#endif
        if (*pin++ != 0x04) { return -11; }
        unsigned char ctlen = *pin++;
        memcpy(out->ciphertext, pin, ctlen); /* copy cipher text */
        out->ciphertext_size = ctlen;
#if 0
        printf ("cipher text: ");
        for (int i = 0; i < out->ciphertext_size; i++){
            printf ("%02x ", out->ciphertext[i]);
        }   printf ("\n");
#endif
    }

    /* e_sm2_c1c3c2, xy,cipher,digest */
    else{
        if (*pin++ != 0x04){ return -12; }

        unsigned char ctlen = *pin++;
        if (ctlen > SM2_MAX_PLAINTEXT_SIZE) { return -13; }
        if (in + ilen - pin != ctlen + (32 + 2)){
            return -14;
        }

        memcpy(out->ciphertext, pin, ctlen); /* copy cipher text */
        out->ciphertext_size = ctlen;
        pin += ctlen;
#if 0
        printf ("cipher text: ");
        for (int i = 0; i < out->ciphertext_size; i++){
            printf ("%02x ", out->ciphertext[i]);
        }   printf ("\n");
#endif
        if (*pin++ != 0x04 || *pin++ != 0x20){ return -15; }

        memcpy(out->digest, pin, 0x20); /* copy digest */
        pin += 0x20;
#if 0
        printf ("digest: ");
        for (int i = 0; i < 32; i++){
            printf ("%02x ", out->digest[i]);
        }   printf ("\n");
#endif
    }

    return 1;
}
