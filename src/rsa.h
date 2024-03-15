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
        #define RSA_OID_DIGEST_MD2     "\x2a\x86\x48\x86\xf7\x0d\x02\x02"
        #define RSA_OID_DIGEST_MD4     "\x2a\x86\x48\x86\xf7\x0d\x02\x04"
        #define RSA_OID_DIGEST_MD5     "\x2a\x86\x48\x86\xf7\x0d\x02\x05"
        #define RSA_OID_DIGEST_SHA1    "\x2b\x0e\x03\x02\x1a"
        #define RSA_OID_DIGEST_SHA256  "\x60\x86\x48\x01\x65\x03\x04\x02\x01"
        #define RSA_OID_DIGEST_SHA384  "\x60\x86\x48\x01\x65\x03\x04\x02\x02"
        #define RSA_OID_DIGEST_SHA512  "\x60\x86\x48\x01\x65\x03\x04\x02\x03"

        #define RSA_SOID_DIGEST_MD2     "1.2.840.113549.2.2"
        #define RSA_SOID_DIGEST_MD4     "1.2.840.113549.2.4"
        #define RSA_SOID_DIGEST_MD5     "1.2.840.113549.2.5"
        #define RSA_SOID_DIGEST_SHA1    "1.3.14.3.2.26"
        #define RSA_SOID_DIGEST_SHA256  "2.16.840.1.101.3.4.2.1"
        #define RSA_SOID_DIGEST_SHA384  "2.16.840.1.101.3.4.2.2"
        #define RSA_SOID_DIGEST_SHA512  "2.16.840.1.101.3.4.2.3"

        /*
        digest size of hash algorithm
            MD2     : 16 bytes
            MD4     : 16 bytes
            MD5     : 16 bytes
            SHA1    : 20 bytes
            SHA256  : 32 bytes
            SHA384  : 48 bytes
            SHA512  : 64 bytes
        */

        /*
            RSAPublicKey ::= SEQUENCE {
                modulus INTEGER, -- n
                publicExponent INTEGER -- e }

            The fields of type RSAPublicKey have the following meanings:
                - modulus is the modulus n.
                -publicExponent is the public exponent e.

            RSAPrivateKey ::= SEQUENCE {
                version Version,
                modulus INTEGER, -- n
                publicExponent INTEGER, -- e
                privateExponent INTEGER, -- d
                prime1 INTEGER, -- p
                prime2 INTEGER, -- q
                exponent1 INTEGER, -- d mod (p-1)
                exponent2 INTEGER, -- d mod (q-1)
                coefficient INTEGER -- (inverse of q) mod p }

            Version ::= INTEGER

            The fields of type RSAPrivateKey have the following meanings:
                - version is the version number, for compatibility with future revisions 
                  of this document. It shall be 0 for this version of the document.
                - modulus is the modulus n.
                - publicExponent is the public exponent e.
                - privateExponent is the private exponent d.
                - prime1 is the prime factor p of n.
                - prime2 is the prime factor q of n.
                - exponent1 is d mod (p-1).
                - exponent2 is d mod (q-1).
                - coefficient is the Chinese Remainder Theorem coefficient q-1 mod p.
        */

        struct rsa_key;

        struct md_method;

        struct rsa_ctx;

        struct rsa_ctx* rsa_new (void);

        void rsa_free (struct rsa_ctx* ctx);

        void rsa_init (struct rsa_ctx* ctx);

        zmerror rsa_import_key (
            struct rsa_ctx* ctx, 
            uint8_t*  n, uint32_t  nlen,
            uint8_t*  e, uint32_t  elen,
            uint8_t*  d, uint32_t  dlen,
            uint8_t*  p, uint32_t  plen,
            uint8_t*  q, uint32_t  qlen,
            uint8_t* dp, uint32_t dplen,
            uint8_t* dq, uint32_t dqlen,
            uint8_t* qp, uint32_t qplen
        );

        int32_t rsa_get_key_bits(struct rsa_ctx* ctx);

        zmerror rsa_gen_key (struct rsa_ctx* ctx, uint32_t bits);

        zmerror rsa_check_pub_key (struct rsa_ctx* ctx);

        zmerror rsa_check_pri_key (struct rsa_ctx* ctx);

        zmerror rsa_rsaes_pkcs1_v15_encrypt           (rsa_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output, uint32_t* olen);
        zmerror rsa_rsaes_pkcs1_v15_decrypt           (rsa_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output, uint32_t* olen);
        zmerror rsa_rsaes_oaep_encrypt                (rsa_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output, uint32_t* olen);
        zmerror rsa_rsaes_oaep_decrypt                (rsa_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output, uint32_t* olen);

        zmerror rsa_rsassa_pkcs1_v15_signature_onshot (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len, uint8_t* digest, uint8_t* sig);
        zmerror rsa_rsassa_pkcs1_v15_verify_onshot    (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len, uint8_t* digest, uint8_t* sig);
        zmerror rsa_rsassa_pss_signature_onshot       (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len, uint8_t* digest, uint8_t* sig);
        zmerror rsa_rsassa_pss_verify_onshot          (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len, uint8_t* digest, uint8_t* sig);

        zmerror rsa_rsassa_pkcs1_v15_signature_init   (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len);
        zmerror rsa_rsassa_pkcs1_v15_signature_update (rsa_ctx* ctx, uint8_t* data, uint32_t dlen);
        zmerror rsa_rsassa_pkcs1_v15_signature_final  (rsa_ctx* ctx, uint8_t* sig);

        zmerror rsa_rsassa_pkcs1_v15_verify_init      (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len);
        zmerror rsa_rsassa_pkcs1_v15_verify_update    (rsa_ctx* ctx, uint8_t* data, uint32_t dlen);
        zmerror rsa_rsassa_pkcs1_v15_verify_final     (rsa_ctx* ctx, uint8_t* sig);

        zmerror rsa_rsassa_pss_signature_init         (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len);
        zmerror rsa_rsassa_pss_signature_update       (rsa_ctx* ctx, uint8_t* data, uint32_t dlen);
        zmerror rsa_rsassa_pss_signature_final        (rsa_ctx* ctx, uint8_t* sig);

        zmerror rsa_rsassa_pss_verify_init             (rsa_ctx* ctx, uint8_t* md_oid, uint32_t oid_len);
        zmerror rsa_rsassa_pss_verify_update           (rsa_ctx* ctx, uint8_t* data, uint32_t dlen);
        zmerror rsa_rsassa_pss_verify_final            (rsa_ctx* ctx, uint8_t* sig);

    #endif
    
#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_RSA_H */
