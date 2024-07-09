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
 *   Date: Nov. 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "zmcrypto.h"
#include "adler32.h"
#include "aes.h"
#include "base16.h"
#include "base32.h"
#include "base58.h"
#include "base64.h"
#include "blockpad.h"
#include "blowfish.h"
#include "cbc.h"
#include "ccm.h"
#include "cfb.h"
#include "cmac.h"
#include "crc32.h"
#include "ctr.h"
#include "des.h"
#include "ecb.h"
#include "ed2k.h"
#include "gcm.h"
#include "hmac.h"
#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "ofb.h"
#include "pbkdf2.h"
#include "rc4.h"
#include "salsa20.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "sm3.h"
#include "sm4.h"
#include "tea.h"
#include "twofish.h"
#include "xtea.h"

#if !defined ZM_ERROR_STRUCT
#   define ZM_ERROR_STRUCT(x) { x, #x }
#endif

/*
example: 
#define ZMCRYPTO_VERSION_NUM    0x01020304
#define ZMCRYPTO_VERSION_STR    "ZmCrypto 0.6.0.0"
*/

#define ZMCRYPTO_VERSION_NUM    0x00010000
#define ZMCRYPTO_VERSION_STR    "ZmCrypto 0.6.0.0"

#ifdef __cplusplus
extern "C" {
#endif

    const uint32_t zm_version_num(void) 
        { return ZMCRYPTO_VERSION_NUM; }
        
    const char* zm_version_str(void) 
        { return ZMCRYPTO_VERSION_STR; }

    struct 
    {
        const int32_t val;
        const char* const str;
    } static const zm_error_code_map[] = {
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_SUCCESSED),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_BASE),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_NULL_PTR),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_KSIZE),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_DSIZE),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_BSIZE),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_TSIZE),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_IVSIZE),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_PAD),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_DATA),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_INVALID_CHAR),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_WEAK_KEY),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_MALLOC),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_OVERFLOW),
        ZM_ERROR_STRUCT(ZMCRYPTO_ERR_CALLBACK), 
    };

    const char* zm_error_str(int32_t code)
    {
        for (uint32_t i = 0; i < sizeof(zm_error_code_map) / sizeof(zm_error_code_map[0]); i++){
            if (zm_error_code_map[i].val == code) { return zm_error_code_map[i].str; }
        }

        static const char* s = "unknown error";
        return s;
    }

    #if defined ZMCRYPTO_ALGO_PBKDF2
        pfn_pbkdf2 _pfn_pbkdf2 = pbkdf2;
        zmerror zm_pbkdf2 (
              void*   (*hash_new)         (void),
              void    (*hash_free)        (void* ctx),
              int32_t (*hash_digest_size) (void),
              int32_t (*hash_block_size)  (void),
              void    (*hash_init)        (void* ctx),
              void    (*hash_starts)      (void* ctx),
              void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dsize),
              void    (*hash_final)       (void* ctx, uint8_t* output),
          uint8_t* p, uint32_t plen, uint8_t* s, uint32_t slen, uint32_t c, uint8_t* dk, uint32_t dklen)
        {
            return _pfn_pbkdf2 (hash_new, hash_free, hash_digest_size, hash_block_size, hash_init, 
                hash_starts, hash_update, hash_final, p, plen, s, slen, c, dk, dklen);
        }
    #endif

    #if defined ZMCRYPTO_ALGO_BLOCKPAD

        pfn_blockpad_zero        _pfn_blockpad_zero       = blockpad_zero;
        pfn_blockpad_iso10126    _pfn_blockpad_iso10126   = blockpad_iso10126;
        pfn_blockpad_ansix923    _pfn_blockpad_ansix923   = blockpad_ansix923;
        pfn_blockpad_pkcs7       _pfn_blockpad_pkcs7      = blockpad_pkcs7;
        pfn_blockdepad_zero      _pfn_blockdepad_zero     = blockdepad_zero;
        pfn_blockdepad_iso10126  _pfn_blockdepad_iso10126 = blockdepad_iso10126;
        pfn_blockdepad_ansix923  _pfn_blockdepad_ansix923 = blockdepad_ansix923;
        pfn_blockdepad_pkcs7     _pfn_blockdepad_pkcs7    = blockdepad_pkcs7;

        zmerror zm_blockpad_zero (uint8_t* data, uint32_t dsize, uint8_t* block, uint32_t blen)
        {
            return _pfn_blockpad_zero (data, dsize, block, blen);
        }

        zmerror zm_blockpad_iso10126 (uint8_t* data, uint32_t dsize, uint8_t* block, uint32_t blen, void (*rng_get_bytes) (uint8_t* data, uint32_t dsize))
        {
            return _pfn_blockpad_iso10126 (data, dsize, block, blen, rng_get_bytes);
        }

        zmerror zm_blockpad_ansix923 (uint8_t* data, uint32_t dsize, uint8_t* block, uint32_t blen)
        {
            return _pfn_blockpad_ansix923 (data, dsize, block, blen);
        }

        zmerror zm_blockpad_pkcs7 (uint8_t* data, uint32_t dsize, uint8_t* block, uint32_t blen)
        {
            return _pfn_blockpad_pkcs7 (data, dsize, block, blen);
        }

        zmerror zm_blockdepad_zero(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dsize)
        {
            return _pfn_blockdepad_zero(block, blen, data, dsize);
        }

        zmerror zm_blockdepad_iso10126(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dsize)
        {
            return _pfn_blockdepad_iso10126(block, blen, data, dsize);
        }

        zmerror zm_blockdepad_ansix923(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dsize)
        {
            return _pfn_blockdepad_ansix923(block, blen, data, dsize);
        }

        zmerror zm_blockdepad_pkcs7(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dsize)
        {
            return _pfn_blockdepad_pkcs7(block, blen, data, dsize);
        }
#endif

#define BINTXT_FUNCTION_IMPL(name)\
        pfn_##name##_encode _pfn_##name##_encode = name##_encode;\
        pfn_##name##_decode _pfn_##name##_decode = name##_decode;\
        zmerror zm_##name##_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)\
        {\
            return _pfn_##name##_encode(input, ilen, output, olen, options);\
        }\
        zmerror zm_##name##_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)\
        {\
            return _pfn_##name##_decode(input, ilen, output, olen, options);\
        }

#define CHECKSUM_FUNCTION_IMPL(name)\
        pfn_##name##_new            _pfn_##name##_new           = name##_new;\
        pfn_##name##_free           _pfn_##name##_free          = name##_free;\
        pfn_##name##_checksum_size  _pfn_##name##_checksum_size = name##_checksum_size;\
        pfn_##name##_init           _pfn_##name##_init          = name##_init;\
        pfn_##name##_starts         _pfn_##name##_starts        = name##_starts;\
        pfn_##name##_update         _pfn_##name##_update        = name##_update;\
        pfn_##name##_final          _pfn_##name##_final         = name##_final;\
\
	    CONTEXT_TYPE_PTR(name) zm_##name##_new(void)\
	    {\
	        return _pfn_##name##_new(); \
        }\
        void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        int32_t zm_##name##_checksum_size(void)\
        {\
            return _pfn_##name##_checksum_size();\
        }\
        void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_init(ctx);\
        }\
        void zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_starts(ctx);\
        }\
        void zm_##name##_update(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dsize)\
        {\
            _pfn_##name##_update(ctx, data, dsize);\
        }\
        void zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
           _pfn_##name##_final(ctx, output);\
        }

    #define HASH_FUNCTION_IMPL(name)\
        pfn_##name##_new         _pfn_##name##_new         = name##_new;\
        pfn_##name##_free        _pfn_##name##_free        = name##_free;\
        pfn_##name##_digest_size _pfn_##name##_digest_size = name##_digest_size;\
        pfn_##name##_block_size  _pfn_##name##_block_size  = name##_block_size;\
        pfn_##name##_init        _pfn_##name##_init        = name##_init;\
        pfn_##name##_starts      _pfn_##name##_starts      = name##_starts;\
        pfn_##name##_update      _pfn_##name##_update      = name##_update;\
        pfn_##name##_final       _pfn_##name##_final       = name##_final;\
\
        CONTEXT_TYPE_PTR(name) zm_##name##_new(void)\
        {\
            return _pfn_##name##_new ();\
        }\
        void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        int32_t zm_##name##_digest_size(void)\
        {\
            return _pfn_##name##_digest_size();\
        }\
        int32_t zm_##name##_block_size(void)\
        {\
            return _pfn_##name##_block_size();\
        }\
        void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_init(ctx);\
        }\
        void zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_starts(ctx);\
        }\
        void zm_##name##_update(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dsize)\
        {\
            _pfn_##name##_update(ctx, data, dsize);\
        }\
        void zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
            _pfn_##name##_final(ctx, output);\
        }

    #define BLOCKCIPHER_FUNCTION_IMPL(name)\
        pfn_##name##_new             _pfn_##name##_new            = name##_new;\
        pfn_##name##_free            _pfn_##name##_free           = name##_free;\
        pfn_##name##_init            _pfn_##name##_init           = name##_init;\
        pfn_##name##_block_size      _pfn_##name##_block_size     = name##_block_size;\
        pfn_##name##_ksize_min       _pfn_##name##_ksize_min      = name##_ksize_min;\
        pfn_##name##_ksize_max       _pfn_##name##_ksize_max      = name##_ksize_max;\
        pfn_##name##_ksize_multiple  _pfn_##name##_ksize_multiple = name##_ksize_multiple;\
        pfn_##name##_set_ekey        _pfn_##name##_set_ekey       = name##_set_ekey;\
        pfn_##name##_set_dkey        _pfn_##name##_set_dkey       = name##_set_dkey;\
        pfn_##name##_enc_block       _pfn_##name##_enc_block      = name##_enc_block;\
        pfn_##name##_dec_block       _pfn_##name##_dec_block      = name##_dec_block;\
\
        CONTEXT_TYPE_PTR(name) zm_##name##_new(void)\
        {\
            return _pfn_##name##_new();\
        }\
        void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_init(ctx);\
        }\
        int32_t zm_##name##_block_size(void)\
        {\
            return _pfn_##name##_block_size();\
        }\
        int32_t zm_##name##_ksize_min(void)\
        {\
            return _pfn_##name##_ksize_min();\
        }\
        int32_t zm_##name##_ksize_max(void)\
        {\
            return _pfn_##name##_ksize_max();\
        }\
        int32_t zm_##name##_ksize_multiple(void)\
        {\
            return _pfn_##name##_ksize_multiple();\
        }\
        zmerror zm_##name##_set_ekey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            return _pfn_##name##_set_ekey(ctx, key, ksize);\
        }\
        zmerror zm_##name##_set_dkey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            return _pfn_##name##_set_dkey(ctx, key, ksize);\
        }\
        void zm_##name##_enc_block(CONTEXT_TYPE_PTR(name) ctx, uint8_t* plaintext, uint8_t* ciphertext)\
        {\
            _pfn_##name##_enc_block(ctx, plaintext, ciphertext);\
        }\
        void zm_##name##_dec_block(CONTEXT_TYPE_PTR(name) ctx, uint8_t* ciphertext, uint8_t* plaintext)\
        {\
            _pfn_##name##_dec_block(ctx, ciphertext, plaintext);\
        }

    #define MAC_FUNCTION_IMPL(name)\
        pfn_##name##_new          _pfn_##name##_new           = name##_new;\
        pfn_##name##_free         _pfn_##name##_free          = name##_free;\
        pfn_##name##_starts       _pfn_##name##_starts        = name##_starts;\
        pfn_##name##_update       _pfn_##name##_update        = name##_update;\
        pfn_##name##_final        _pfn_##name##_final         = name##_final;\
        pfn_##name##_digest_size  _pfn_##name##_digest_size   = name##_digest_size;\
\
        CONTEXT_TYPE_PTR(name) zm_##name##_new (void)\
        {\
            return _pfn_##name##_new();\
        }\
        void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        zmerror zm_##name##_starts (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t klen)\
        {\
            return _pfn_##name##_starts(ctx, key, klen);\
        }\
        void zm_##name##_update (CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dsize)\
        {\
            _pfn_##name##_update(ctx, data, dsize);\
        }\
        void zm_##name##_final (CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
            _pfn_##name##_final(ctx, output);\
        }\
        int32_t zm_##name##_digest_size (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            return _pfn_##name##_digest_size(ctx);\
        }

    #define CIPHER_MODE_FUNCTION_IMPL(name, param, args)\
        pfn_##name##_new       _pfn_##name##_new      = name##_new;\
        pfn_##name##_free      _pfn_##name##_free     = name##_free;\
        pfn_##name##_init      _pfn_##name##_init     = name##_init;\
        pfn_##name##_set_ekey  _pfn_##name##_set_ekey = name##_set_ekey;\
        pfn_##name##_set_dkey  _pfn_##name##_set_dkey = name##_set_dkey;\
        pfn_##name##_enc       _pfn_##name##_enc      = name##_enc;\
        pfn_##name##_dec       _pfn_##name##_dec      = name##_dec;\
\
        CONTEXT_TYPE_PTR(name) zm_##name##_new (void)\
        {\
            return _pfn_##name##_new();\
        }\
        void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        void zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx, param)\
        {\
            _pfn_##name##_init(ctx, args);\
        }\
        zmerror zm_##name##_set_ekey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            return _pfn_##name##_set_ekey(ctx, key, ksize);\
        }\
        zmerror zm_##name##_set_dkey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            return _pfn_##name##_set_dkey(ctx, key, ksize);\
        }\
        zmerror zm_##name##_enc (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            return _pfn_##name##_enc(ctx, input, ilen, output);\
        }\
        zmerror zm_##name##_dec (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            return _pfn_##name##_dec(ctx, input, ilen, output);\
        }

    #define CIPHER_MODE_WITH_IV_FUNCTION_IMPL(name, param, args)\
        pfn_##name##_new      _pfn_##name##_new       = name##_new;\
        pfn_##name##_free     _pfn_##name##_free      = name##_free;\
        pfn_##name##_init     _pfn_##name##_init      = name##_init;\
        pfn_##name##_set_ekey _pfn_##name##_set_ekey  = name##_set_ekey;\
        pfn_##name##_set_dkey _pfn_##name##_set_dkey  = name##_set_dkey;\
        pfn_##name##_enc      _pfn_##name##_enc       = name##_enc;\
        pfn_##name##_dec      _pfn_##name##_dec       = name##_dec;\
\
        CONTEXT_TYPE_PTR(name) zm_##name##_new (void)\
        {\
            return _pfn_##name##_new();\
        }\
        void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        void zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx, param)\
        {\
            _pfn_##name##_init(ctx, args);\
        }\
        zmerror zm_##name##_set_ekey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)\
        {\
            return _pfn_##name##_set_ekey(ctx, key, ksize, iv, ivsize);\
        }\
        zmerror zm_##name##_set_dkey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)\
        {\
            return _pfn_##name##_set_dkey(ctx, key, ksize, iv, ivsize);\
        }\
        zmerror zm_##name##_enc (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            return _pfn_##name##_enc(ctx, input, ilen, output);\
        }\
        zmerror zm_##name##_dec (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            return _pfn_##name##_dec(ctx, input, ilen, output);\
        }

    #if defined ZMCRYPTO_ALGO_HMAC
        MAC_FUNCTION_IMPL(hmac)
        pfn_hmac_init _pfn_hmac_init = hmac_init;
        void zm_hmac_init (CONTEXT_TYPE_PTR(hmac) ctx, HMAC_INIT_PARAM)
        {
            _pfn_hmac_init (ctx, HMAC_INIT_ARGS); 
        }
    #endif

    #if defined ZMCRYPTO_ALGO_CMAC
        MAC_FUNCTION_IMPL(cmac)
        pfn_cmac_init _pfn_cmac_init = cmac_init;
        void zm_cmac_init (CONTEXT_TYPE_PTR(cmac) ctx, CMAC_INIT_PARAM)
        {
            _pfn_cmac_init(ctx, CMAC_INIT_ARGS); 
        }
    #endif

    #define AEAD_FUNCTION_IMPL(name, cipher_param, cipher_args, starts_param, starts_args, final_param, final_args)\
        pfn_##name##_new             _pfn_##name##_new         = name##_new         ;\
        pfn_##name##_free            _pfn_##name##_free        = name##_free        ;\
        pfn_##name##_init            _pfn_##name##_init        = name##_init        ;\
        pfn_##name##_starts          _pfn_##name##_starts      = name##_starts      ;\
        pfn_##name##_update_aad      _pfn_##name##_update_aad  = name##_update_aad  ;\
        pfn_##name##_update_data     _pfn_##name##_update_data = name##_update_data ;\
        pfn_##name##_final           _pfn_##name##_final       = name##_final       ;\
\
        CONTEXT_TYPE_PTR(name) zm_##name##_new (void)\
        {\
            return _pfn_##name##_new();\
        }\
        void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            _pfn_##name##_free(ctx);\
        }\
        void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx, cipher_param)\
        {\
            _pfn_##name##_init(ctx, cipher_args);\
        }\
        zmerror zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx, starts_param)\
        {\
            return _pfn_##name##_starts(ctx, starts_args);\
        }\
        zmerror zm_##name##_update_aad(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dsize)\
        {\
            return _pfn_##name##_update_aad(ctx, data, dsize);\
        }\
        zmerror zm_##name##_update_data(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dsize, uint8_t *output)\
        {\
            return _pfn_##name##_update_data(ctx, data, dsize, output);\
        }\
        zmerror zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, final_param)\
        {\
            return _pfn_##name##_final(ctx, final_args);\
        }

    #define STREAMCIPHER_FUNCTION_IMPL(name)\
        pfn_##name##_ksize_min        _pfn_##name##_ksize_min      = name##_ksize_min      ;\
        pfn_##name##_ksize_max        _pfn_##name##_ksize_max      = name##_ksize_max      ;\
        pfn_##name##_ksize_multiple   _pfn_##name##_ksize_multiple = name##_ksize_multiple ;\
        pfn_##name##_new              _pfn_##name##_new            = name##_new            ;\
        pfn_##name##_free             _pfn_##name##_free           = name##_free           ;\
        pfn_##name##_init             _pfn_##name##_init           = name##_init           ;\
        pfn_##name##_set_ekey         _pfn_##name##_set_ekey       = name##_set_ekey       ;\
        pfn_##name##_set_dkey         _pfn_##name##_set_dkey       = name##_set_dkey       ;\
        pfn_##name##_encrypt          _pfn_##name##_encrypt        = name##_encrypt        ;\
        pfn_##name##_decrypt          _pfn_##name##_decrypt        = name##_decrypt        ;\
\
        int32_t zm_##name##_ksize_min (void) \
            { return _pfn_##name##_ksize_min(); }\
        int32_t zm_##name##_ksize_max (void) \
            { return _pfn_##name##_ksize_max(); }\
        int32_t zm_##name##_ksize_multiple (void) \
            { return _pfn_##name##_ksize_multiple(); }\
        CONTEXT_TYPE_PTR(name) zm_##name##_new (void) \
            { return _pfn_##name##_new(); }\
        void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx) \
            { _pfn_##name##_free(ctx); }\
        void zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx) \
            { _pfn_##name##_init(ctx); }\
        zmerror zm_##name##_set_ekey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize) \
            { return _pfn_##name##_set_ekey(ctx, key, ksize); }\
        zmerror zm_##name##_set_dkey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize) \
            { return _pfn_##name##_set_dkey(ctx, key, ksize); }\
        void zm_##name##_encrypt(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output) \
            { _pfn_##name##_encrypt(ctx, input, ilen, output); }\
        void zm_##name##_decrypt(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output) \
            { _pfn_##name##_decrypt(ctx, input, ilen, output); }

    #define STREAMCIPHER_WITH_IV_FUNCTION_IMPL(name)\
        pfn_##name##_set_iv _pfn_##name##_set_iv = name##_set_iv;\
        zmerror zm_##name##_set_iv(CONTEXT_TYPE_PTR(name) ctx, uint8_t* iv) { return _pfn_##name##_set_iv(ctx, iv); }

    #if defined ZMCRYPTO_ALGO_CCM
        AEAD_FUNCTION_IMPL(ccm, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS, CCM_STARTS_PARAM, CCM_STARTS_ARGS, CCM_FINAL_PARAM, CCM_FINAL_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_GCM
        AEAD_FUNCTION_IMPL(gcm, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS, GCM_STARTS_PARAM, GCM_STARTS_ARGS, GCM_FINAL_PARAM, GCM_FINAL_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE64
        BINTXT_FUNCTION_IMPL(base64)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE58
        BINTXT_FUNCTION_IMPL(base58)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE32
        BINTXT_FUNCTION_IMPL(base32)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE16
        BINTXT_FUNCTION_IMPL(base16)
    #endif

    #if defined ZMCRYPTO_ALGO_ADLER32
        CHECKSUM_FUNCTION_IMPL(adler32)
    #endif

    #if defined ZMCRYPTO_ALGO_CRC32
        CHECKSUM_FUNCTION_IMPL(crc32)
    #endif

    #if defined ZMCRYPTO_ALGO_MD5
        HASH_FUNCTION_IMPL(md5)
    #endif

    #if defined ZMCRYPTO_ALGO_MD4
        HASH_FUNCTION_IMPL(md4)
    #endif

    #if defined ZMCRYPTO_ALGO_MD2
        HASH_FUNCTION_IMPL(md2)
    #endif

    #if defined ZMCRYPTO_ALGO_ED2K
        HASH_FUNCTION_IMPL(ed2k)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA1
        HASH_FUNCTION_IMPL(sha1)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA2
        HASH_FUNCTION_IMPL(sha224)
        HASH_FUNCTION_IMPL(sha256)
        HASH_FUNCTION_IMPL(sha384)
        HASH_FUNCTION_IMPL(sha512)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA3
        HASH_FUNCTION_IMPL(sha3_224)
        HASH_FUNCTION_IMPL(sha3_256)
        HASH_FUNCTION_IMPL(sha3_384)
        HASH_FUNCTION_IMPL(sha3_512)
    #endif

    #if defined ZMCRYPTO_ALGO_SM3
        HASH_FUNCTION_IMPL(sm3)
    #endif

    #if defined ZMCRYPTO_ALGO_AES
        BLOCKCIPHER_FUNCTION_IMPL(aes)
    #endif

    #if defined ZMCRYPTO_ALGO_BLOWFISH
        BLOCKCIPHER_FUNCTION_IMPL(blowfish)
    #endif

    #if defined ZMCRYPTO_ALGO_TWOFISH
        BLOCKCIPHER_FUNCTION_IMPL(twofish)
    #endif
    
    #if defined ZMCRYPTO_ALGO_DES
        BLOCKCIPHER_FUNCTION_IMPL(des)
    #endif
    
    #if defined ZMCRYPTO_ALGO_TEA
        BLOCKCIPHER_FUNCTION_IMPL(tea)
    #endif
    
    #if defined ZMCRYPTO_ALGO_XTEA
        BLOCKCIPHER_FUNCTION_IMPL(xtea)
    #endif

    #if defined ZMCRYPTO_ALGO_SM4
        BLOCKCIPHER_FUNCTION_IMPL(sm4)
    #endif

    #if defined ZMCRYPTO_ALGO_ECB
        CIPHER_MODE_FUNCTION_IMPL(ecb, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_CBC
        CIPHER_MODE_WITH_IV_FUNCTION_IMPL(cbc, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS)
    #endif
    
    #if defined ZMCRYPTO_ALGO_CFB
        CIPHER_MODE_WITH_IV_FUNCTION_IMPL(cfb, CIPHER_MODE_INIT_PARAM_2, CIPHER_MODE_INIT_ARGS_2)
    #endif
    
    #if defined ZMCRYPTO_ALGO_OFB
        CIPHER_MODE_WITH_IV_FUNCTION_IMPL(ofb, CIPHER_MODE_INIT_PARAM_2, CIPHER_MODE_INIT_ARGS_2)
    #endif
    
    #if defined ZMCRYPTO_ALGO_CTR
        CIPHER_MODE_WITH_IV_FUNCTION_IMPL(ctr, CIPHER_MODE_INIT_PARAM_2, CIPHER_MODE_INIT_ARGS_2)
    #endif

    #if defined ZMCRYPTO_ALGO_RC4
        STREAMCIPHER_FUNCTION_IMPL(rc4)
    #endif

    #if defined ZMCRYPTO_ALGO_SALSA20
        STREAMCIPHER_FUNCTION_IMPL(salsa20)
        STREAMCIPHER_WITH_IV_FUNCTION_IMPL(salsa20)

        STREAMCIPHER_FUNCTION_IMPL(xsalsa20)
        STREAMCIPHER_WITH_IV_FUNCTION_IMPL(xsalsa20)
    #endif

    uint32_t zm_string_len(const char* s)
    {
        uint32_t len = 0;
        while (*s)
            { len++; s++; if (len > ZMCRYPTO_MAX_STRLEN) { return ZMCRYPTO_MAX_STRLEN; } }
        return len;
    }

    zmbool zm_string_equals(const char* s1, const char* s2)
    {
        uint32_t len1 = zm_string_len(s1);
        uint32_t len2 = zm_string_len(s2);
        if (len1 == len2)
            { return (zmcrypto_memcmp(s1, s2, len1) == 0) ? zmtrue : zmfalse; }
        else
            { return 0; }        
    }

    const void* zm_replace_fnc(const char* fname, void* pfn)
    {
        if (zm_string_equals(fname, "zm_aes_block_size") == zmtrue) 
            { void* p = _pfn_aes_block_size; _pfn_aes_block_size = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_dec_block") == zmtrue) 
            { void* p = _pfn_aes_dec_block; _pfn_aes_dec_block = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_enc_block") == zmtrue) 
            { void* p = _pfn_aes_enc_block; _pfn_aes_enc_block = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_free") == zmtrue) 
            { void* p = _pfn_aes_free; _pfn_aes_free = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_init") == zmtrue) 
            { void* p = _pfn_aes_init; _pfn_aes_init = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_ksize_max") == zmtrue) 
            { void* p = _pfn_aes_ksize_max; _pfn_aes_ksize_max = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_ksize_min") == zmtrue) 
            { void* p = _pfn_aes_ksize_min; _pfn_aes_ksize_min = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_ksize_multiple") == zmtrue) 
            { void* p = _pfn_aes_ksize_multiple; _pfn_aes_ksize_multiple = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_new") == zmtrue) 
            { void* p = _pfn_aes_new; _pfn_aes_new = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_set_dkey") == zmtrue) 
            { void* p = _pfn_aes_set_dkey; _pfn_aes_set_dkey = pfn; return p; }
        if (zm_string_equals(fname, "zm_aes_set_ekey") == zmtrue) 
            { void* p = _pfn_aes_set_ekey; _pfn_aes_set_ekey = pfn; return p; }

        return NULL;
    }

    const void* zm_get_orig_fnc(const char* fname)
    {
        if (zm_string_equals(fname, "zm_aes_block_size") == zmtrue) 
            { return aes_block_size; }
        if (zm_string_equals(fname, "zm_aes_dec_block") == zmtrue) 
            { return aes_dec_block; }
        if (zm_string_equals(fname, "zm_aes_enc_block") == zmtrue) 
            { return aes_enc_block; }
        if (zm_string_equals(fname, "zm_aes_free") == zmtrue) 
            { return aes_free; }
        if (zm_string_equals(fname, "zm_aes_init") == zmtrue) 
            { return aes_init; }
        if (zm_string_equals(fname, "zm_aes_ksize_max") == zmtrue) 
            { return aes_ksize_max; }
        if (zm_string_equals(fname, "zm_aes_ksize_min") == zmtrue) 
            { return aes_ksize_min; }
        if (zm_string_equals(fname, "zm_aes_ksize_multiple") == zmtrue) 
            { return aes_ksize_multiple; }
        if (zm_string_equals(fname, "zm_aes_new") == zmtrue) 
            {  return aes_new; }
        if (zm_string_equals(fname, "zm_aes_set_dkey") == zmtrue) 
            { return aes_set_dkey; }
        if (zm_string_equals(fname, "zm_aes_set_ekey") == zmtrue) 
            { return aes_set_ekey; }
        return NULL;
    }

#ifdef __cplusplus
}
#endif
