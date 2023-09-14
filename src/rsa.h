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
 *   Date: Sep 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_RSA_H
#define ZMCRYPTO_RSA_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_RSA
        #define OID_DIGEST_MD2     "\x2a\x86\x48\x86\xf7\x0d\x02\x02"
        #define OID_DIGEST_MD4     "\x2a\x86\x48\x86\xf7\x0d\x02\x04"
        #define OID_DIGEST_MD5     "\x2a\x86\x48\x86\xf7\x0d\x02\x05"
        #define OID_DIGEST_SHA1    "\x2b\x0e\x03\x02\x1a"
        #define OID_DIGEST_SHA256  "\x60\x86\x48\x01\x65\x03\x04\x02\x01"
        #define OID_DIGEST_SHA384  "\x60\x86\x48\x01\x65\x03\x04\x02\x02"
        #define OID_DIGEST_SHA512  "\x60\x86\x48\x01\x65\x03\x04\x02\x03"

        #define SOID_DIGEST_MD2     "1.2.840.113549.2.2"
        #define SOID_DIGEST_MD4     "1.2.840.113549.2.4"
        #define SOID_DIGEST_MD5     "1.2.840.113549.2.5"
        #define SOID_DIGEST_SHA1    "1.3.14.3.2.26"
        #define SOID_DIGEST_SHA256  "2.16.840.1.101.3.4.2.1"
        #define SOID_DIGEST_SHA384  "2.16.840.1.101.3.4.2.2"
        #define SOID_DIGEST_SHA512  "2.16.840.1.101.3.4.2.3"

        typedef struct
        {
            uint8_t*  n; uint32_t  nlen; /* modulus                   */
            uint8_t*  e; uint32_t  elen; /* public exponent           */
            uint8_t*  d; uint32_t  dlen; /* private exponent          */
            uint8_t*  p; uint32_t  plen; /* prime1                    */
            uint8_t*  q; uint32_t  qlen; /* prime2                    */
            uint8_t* dp; uint32_t dplen; /* exponent1 -- d mod (p-1)  */
            uint8_t* dq; uint32_t dqlen; /* exponent2 -- d mod (q-1)  */
            uint8_t* qp; uint32_t qplen; /* (inverse of q) mod p      */
        } rsa_ctx;

        rsa_ctx* rsa_new (
            void
        );

        void rsa_free (
            rsa_ctx* ctx
        );

        void rsa_init (
            rsa_ctx* ctx
        );

        zmerror rsa_set (
            rsa_ctx* ctx, 
            uint8_t* n, uint32_t nlen,
            uint8_t* e, uint32_t elen,
            uint8_t* d, uint32_t dlen,
            uint8_t* p, uint32_t plen,
            uint8_t* q, uint32_t qlen,
            uint8_t* dp, uint32_t dplen,
            uint8_t* dq, uint32_t dqlen,
            uint8_t* qp, uint32_t qplen
        );

        zmerror rsa_gen (
            rsa_ctx* ctx, 
            uint32_t bits,
            void (*f_rng)(void *, uint8_t*, uint32_t), 
            void *p_rng
        );

        zmerror rsa_check_pub_key (
            rsa_ctx* ctx
        );

        zmerror rsa_check_pri_key (
            rsa_ctx* ctx
        );

        // zmerror rsa_rsaes_pkcs1_v15_enc (rsa_ctx* ctx, ...);
        // zmerror rsa_rsaes_pkcs1_v15_dec (rsa_ctx* ctx, ...);
        // zmerror rsa_rsaes_oaep_enc      (rsa_ctx* ctx, ...);
        // zmerror rsa_rsaes_oaep_dec      (rsa_ctx* ctx, ...);

        //zmerror rsa_rsassa_pkcs1_v15_sign   (rsa_ctx* ctx, ...);
        //zmerror rsa_rsassa_pkcs1_v15_verify (rsa_ctx* ctx, ...);
        //zmerror rsa_rsassa_pss_sign         (rsa_ctx* ctx, ...);
        //zmerror rsa_rsassa_pss_verify       (rsa_ctx* ctx, ...);

    #endif
    
#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_RSA_H */
