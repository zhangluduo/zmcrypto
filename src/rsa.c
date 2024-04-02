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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "rsa.h"

#if defined ZMCRYPTO_ALGO_RSA

        struct rsa_key
        {
            uint8_t*  n; uint32_t  nlen; /* modulus                   */
            uint8_t*  e; uint32_t  elen; /* public exponent           */
            uint8_t*  d; uint32_t  dlen; /* private exponent          */
            uint8_t*  p; uint32_t  plen; /* prime1                    */
            uint8_t*  q; uint32_t  qlen; /* prime2                    */
            uint8_t* dp; uint32_t dplen; /* exponent1 -- d mod (p-1)  */
            uint8_t* dq; uint32_t dqlen; /* exponent2 -- d mod (q-1)  */
            uint8_t* qp; uint32_t qplen; /* (inverse of q) mod p      */
        };

        struct md_method
        {
            void* md_ctx;
            void* md_new (void);
            void md_free (void* ctx);
            int32_t md_digest_size (void);
            int32_t md_block_size (void);
            void md_init (void* ctx);
            void md_starts (void* ctx);
            void md_update (void* ctx, uint8_t* data, uint32_t dlen);
            void md_final (void* ctx, uint8_t* output);
        }

        struct rsa_ctx
        {
            int xxxxxxx;
        } ;

#if 0
            /*The key for RSA operation*/
            struct rsa_key key;
            struct md_method md;

            /* optional: random number generator */
            int32_t (*rng_func)(void* param, uint8_t* buffer, uint32_t blen);
            void* rng_param;

            /* optional: used for the MGF mask generating function in the
               EME-OAEP and EMSA-PSS encodings.  */
            uint8_t* md_oid;
            uint32_t oid_size;

            /* optional: label for RSAES-OAEP */
            uint8_t* label;
            uint32_t llen;

            /* optional: salt for RSAES-PSS */
            uint8_t* salt;
            uint32_t slen;
#endif /*if 0*/

#endif /* ZMCRYPTO_ALGO_RSA */
