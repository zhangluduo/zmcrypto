/**
 *  Copyright 2022 The ZmCrypto Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * 
 * Author: Zhang Luduo (zhangluduo@qq.com)
 *   Date: Nov 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "pbkdf2.h"
#include "hmac.h"

/* rfc2898 */

/*
DK = PBKDF2(PRF, Password, Salt, c, dkLen)

where:
    PRF is a pseudorandom function of two parameters with
    output length hLen (e.g., a keyed HMAC)
    Password is the master password from which a derived
    key is generated
    Salt is a sequence of bits, known as a cryptographic salt
    c is the number of iterations desired
    dkLen is the desired bit-length of the derived key
    DK is the generated derived key
*/

#if defined ZMCRYPTO_ALGO_PBKDF2

    #if !defined ZMCRYPTO_ALGO_HMAC
        #error The macro 'ZMCRYPTO_ALGO_HMAC' is undefined.
    #endif

    void pbkdf2_do_xor(uint8_t* buf, const uint8_t* mask, uint32_t count)
    {
        for (uint32_t i = 0; i < count; i++){
            buf[i] ^= mask[i];
        }
    }

    zmerror pbkdf2(
        void*   (*hash_new)         (void),
        void    (*hash_free)        (void* ctx),
        int32_t (*hash_digest_size) (void),
        int32_t (*hash_block_size)  (void),
        void    (*hash_init)        (void* ctx),
        void    (*hash_starts)      (void* ctx),
        void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dlen),
        void    (*hash_final)       (void* ctx, uint8_t* output),
        uint8_t* p, uint32_t plen, uint8_t* s, uint32_t slen, uint32_t c, uint8_t* dk, uint32_t dklen)
    {
        if (!hash_new || !hash_free || !hash_digest_size || !hash_block_size || !hash_init ||
            !hash_starts || !hash_update || !hash_final || !p || !s || !dk){
            return ZMCRYPTO_ERR_NULL_PTR;
        }

        if (plen == 0 || slen == 0 || dklen == 0){
            return ZMCRYPTO_ERR_INVALID_DSIZE;
        }

        struct hmac_ctx _hmac_ctx;
        hmac_init(&_hmac_ctx, hash_new, hash_free, hash_digest_size, hash_block_size, hash_init, hash_starts, hash_update, hash_final);

        uint8_t digest[DIGEST_MAX_SIZE];
        uint32_t hlen = hash_digest_size();
        uint32_t loop = (dklen + (hlen - 1)) / hlen;
        uint32_t offset = 0;
        
        for (uint32_t i = 0; i < loop; i++){
            hmac_starts(&_hmac_ctx, p, plen);
            hmac_update(&_hmac_ctx, s, slen);
            for (uint32_t j = 0; j < 4; j++)
            {
                #if defined ENDIAN_LITTLE
                    uint8_t b = (uint8_t)((i + 1) >> ((3 - j) * 8));
                #else
                    uint8_t b = (uint8_t)((i + 1) >> ((j) * 8));
                #endif
                
                hmac_update(&_hmac_ctx, &b, 1);
            }
            hmac_final(&_hmac_ctx, digest);

            uint32_t seglen = (offset + hlen > dklen) ? (dklen - hlen * i) : (hlen);
            zmcrypto_memcpy(dk + offset, digest, seglen);

            for (uint32_t j = 1; j < c; j++)
            {
                hmac_starts(&_hmac_ctx, p, plen);
                hmac_update(&_hmac_ctx, digest, hlen);
                hmac_final(&_hmac_ctx, digest);
                pbkdf2_do_xor(dk + offset, digest, seglen);
            }

            offset += seglen;
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_ALGO_PBKDF2 */
