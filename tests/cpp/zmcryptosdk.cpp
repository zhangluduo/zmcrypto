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
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"

namespace zmcrypto
{
    pfn_version_num   _pfn_version_num  = NULL;
    pfn_version_str   _pfn_version_str  = NULL;
    pfn_error_str     _pfn_error_str    = NULL;
    pfn_replace_fnc   _pfn_replace_fnc  = NULL;

    #if defined ZMCRYPTO_ALGO_PBKDF2
        pfn_pbkdf2 _pfn_pbkdf2 = NULL;

        zmerror sdk::zm_pbkdf2 (
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
            if (_pfn_pbkdf2)
            {
                return _pfn_pbkdf2(hash_new, hash_free, hash_digest_size, hash_block_size, hash_init, 
                    hash_starts, hash_update, hash_final, p, plen, s, slen, c, dk, dklen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
    #endif

    #if defined ZMCRYPTO_ALGO_BLOCKPAD
        pfn_blockpad_zero       _pfn_blockpad_zero        = NULL;
        pfn_blockpad_iso10126   _pfn_blockpad_iso10126    = NULL;
        pfn_blockpad_ansix923   _pfn_blockpad_ansix923    = NULL;
        pfn_blockpad_pkcs7      _pfn_blockpad_pkcs7       = NULL;
        pfn_blockdepad_zero     _pfn_blockdepad_zero      = NULL;
        pfn_blockdepad_iso10126 _pfn_blockdepad_iso10126  = NULL;
        pfn_blockdepad_ansix923 _pfn_blockdepad_ansix923  = NULL;
        pfn_blockdepad_pkcs7    _pfn_blockdepad_pkcs7     = NULL;

        zmerror sdk::zm_blockpad_zero (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen)
        {
            if (_pfn_blockpad_zero){
                return _pfn_blockpad_zero (data, dlen, block, blen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockpad_iso10126 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen, void (*rng_get_bytes) (uint8_t* data, uint32_t dlen))
        {
            if (_pfn_blockpad_iso10126){
                return _pfn_blockpad_iso10126 (data, dlen, block, blen, rng_get_bytes);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockpad_ansix923 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen)
        {
            if (_pfn_blockpad_ansix923){
                return _pfn_blockpad_ansix923 (data, dlen, block, blen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockpad_pkcs7 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen)
        {
            if (_pfn_blockpad_pkcs7){
                return _pfn_blockpad_pkcs7 (data, dlen, block, blen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockdepad_zero(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen)
        {
            if (_pfn_blockdepad_zero){
                return _pfn_blockdepad_zero (block, blen, data, dlen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockdepad_iso10126(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen)
        {
            if (_pfn_blockdepad_iso10126){
                return _pfn_blockdepad_iso10126 (block, blen, data, dlen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockdepad_ansix923(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen)
        {
            if (_pfn_blockdepad_ansix923){
                return _pfn_blockdepad_ansix923 (block, blen, data, dlen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
        zmerror sdk::zm_blockdepad_pkcs7(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen)
        {
            if (_pfn_blockdepad_pkcs7){
                return _pfn_blockdepad_pkcs7 (block, blen, data, dlen);
            }
            return ZMCRYPTO_ERR_NULL_PTR;
        }
    #endif

    /**
     * Binary to Text Encoders and Decoders
     */

     #define BINTXT_POINTER_DECLARA(name)\
        pfn_##name##_encode _pfn_##name##_encode = NULL;\
        pfn_##name##_decode _pfn_##name##_decode = NULL;

     #define BINTXT_POINTER_LOAD(name)\
        _pfn_##name##_encode = (pfn_##name##_encode)GetProcAddress(m_modulehandle, "zm_" #name "_encode");\
        _pfn_##name##_decode = (pfn_##name##_decode)GetProcAddress(m_modulehandle, "zm_" #name "_decode");

    #define BINTXT_POINTER_IMPL(name)\
        zmerror sdk::zm_##name##_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)\
        {\
            if (_pfn_##name##_encode){\
                return _pfn_##name##_encode(input, ilen, output, olen, options);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)\
        {\
            if (_pfn_##name##_decode){\
                return _pfn_##name##_decode(input, ilen, output, olen, options);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }

    /**
     * Non-Cryptographic Checksums
     */

    #define CHECKSUM_POINTER_DECLARA(name)\
        pfn_##name##_new           _pfn_##name##_new           = NULL;\
        pfn_##name##_free          _pfn_##name##_free          = NULL;\
        pfn_##name##_checksum_size _pfn_##name##_checksum_size = NULL;\
        pfn_##name##_init          _pfn_##name##_init          = NULL;\
        pfn_##name##_starts        _pfn_##name##_starts        = NULL;\
        pfn_##name##_update        _pfn_##name##_update        = NULL;\
        pfn_##name##_final         _pfn_##name##_final         = NULL;

    #define CHECKSUM_POINTER_LOAD(name)\
        _pfn_##name##_new              = (pfn_##name##_new            )GetProcAddress(m_modulehandle, "zm_" #name "_new"            );\
        _pfn_##name##_free             = (pfn_##name##_free           )GetProcAddress(m_modulehandle, "zm_" #name "_free"           );\
        _pfn_##name##_checksum_size    = (pfn_##name##_checksum_size  )GetProcAddress(m_modulehandle, "zm_" #name "_checksum_size"  );\
        _pfn_##name##_init             = (pfn_##name##_init           )GetProcAddress(m_modulehandle, "zm_" #name "_init"           );\
        _pfn_##name##_starts           = (pfn_##name##_starts         )GetProcAddress(m_modulehandle, "zm_" #name "_starts"         );\
        _pfn_##name##_update           = (pfn_##name##_update         )GetProcAddress(m_modulehandle, "zm_" #name "_update"         );\
        _pfn_##name##_final            = (pfn_##name##_final          )GetProcAddress(m_modulehandle, "zm_" #name "_final"          );

    #define CHECKSUM_POINTER_IMPL(name)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new(void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        int32_t sdk::zm_##name##_checksum_size(void)\
        {\
            if (_pfn_##name##_checksum_size){\
                return _pfn_##name##_checksum_size();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        void sdk::zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx);\
            }\
        }\
        void sdk::zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_starts){\
                _pfn_##name##_starts(ctx);\
            }\
        }\
        void sdk::zm_##name##_update(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen)\
        {\
            if (_pfn_##name##_update){\
                _pfn_##name##_update(ctx, data, dlen);\
            }\
        }\
        void sdk::zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
            if (_pfn_##name##_final){\
                _pfn_##name##_final(ctx, output);\
            }\
        }

    #define HASH_POINTER_DECLARA(name)\
        pfn_##name##_new         _pfn_##name##_new         = NULL;\
        pfn_##name##_free        _pfn_##name##_free        = NULL;\
        pfn_##name##_digest_size _pfn_##name##_digest_size = NULL;\
        pfn_##name##_block_size  _pfn_##name##_block_size  = NULL;\
        pfn_##name##_init        _pfn_##name##_init        = NULL;\
        pfn_##name##_starts      _pfn_##name##_starts      = NULL;\
        pfn_##name##_update      _pfn_##name##_update      = NULL;\
        pfn_##name##_final       _pfn_##name##_final       = NULL;

    #define HASH_POINTER_LOAD(name)\
        _pfn_##name##_new            = (pfn_##name##_new          )GetProcAddress(m_modulehandle, "zm_" #name "_new"          );\
        _pfn_##name##_free           = (pfn_##name##_free         )GetProcAddress(m_modulehandle, "zm_" #name "_free"         );\
        _pfn_##name##_digest_size    = (pfn_##name##_digest_size  )GetProcAddress(m_modulehandle, "zm_" #name "_digest_size"  );\
        _pfn_##name##_block_size     = (pfn_##name##_block_size   )GetProcAddress(m_modulehandle, "zm_" #name "_block_size"   );\
        _pfn_##name##_init           = (pfn_##name##_init         )GetProcAddress(m_modulehandle, "zm_" #name "_init"         );\
        _pfn_##name##_starts         = (pfn_##name##_starts       )GetProcAddress(m_modulehandle, "zm_" #name "_starts"       );\
        _pfn_##name##_update         = (pfn_##name##_update       )GetProcAddress(m_modulehandle, "zm_" #name "_update"       );\
        _pfn_##name##_final          = (pfn_##name##_final        )GetProcAddress(m_modulehandle, "zm_" #name "_final"        );

    #define HASH_POINTER_IMPL(name)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new(void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        int32_t sdk::zm_##name##_digest_size(void)\
        {\
            if (_pfn_##name##_digest_size){\
                return _pfn_##name##_digest_size();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_block_size(void)\
        {\
            if (_pfn_##name##_block_size){\
                return _pfn_##name##_block_size();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        void sdk::zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx);\
            }\
        }\
        void sdk::zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_starts){\
                _pfn_##name##_starts(ctx);\
            }\
        }\
        void sdk::zm_##name##_update(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen)\
        {\
            if (_pfn_##name##_update){\
                _pfn_##name##_update(ctx, data, dlen);\
            }\
        }\
        void sdk::zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
            if (_pfn_##name##_final){\
                _pfn_##name##_final(ctx, output);\
            }\
        }

    /**
     * Block cipher 
     */

    #define BLOCKCIPHER_POINTER_DECLARA(name)\
        pfn_##name##_new            _pfn_##name##_new            = NULL;\
        pfn_##name##_free           _pfn_##name##_free           = NULL;\
        pfn_##name##_init           _pfn_##name##_init           = NULL;\
        pfn_##name##_block_size     _pfn_##name##_block_size     = NULL;\
        pfn_##name##_ksize_min      _pfn_##name##_ksize_min      = NULL;\
        pfn_##name##_ksize_max      _pfn_##name##_ksize_max      = NULL;\
        pfn_##name##_ksize_multiple _pfn_##name##_ksize_multiple = NULL;\
        pfn_##name##_set_ekey       _pfn_##name##_set_ekey       = NULL;\
        pfn_##name##_set_dkey       _pfn_##name##_set_dkey       = NULL;\
        pfn_##name##_enc_block      _pfn_##name##_enc_block      = NULL;\
        pfn_##name##_dec_block      _pfn_##name##_dec_block      = NULL;

    #define BLOCKCIPHER_POINTER_LOAD(name)\
        _pfn_##name##_new            = (pfn_##name##_new           )GetProcAddress(m_modulehandle, "zm_" #name "_new"           );\
        _pfn_##name##_free           = (pfn_##name##_free          )GetProcAddress(m_modulehandle, "zm_" #name "_free"          );\
        _pfn_##name##_init           = (pfn_##name##_init          )GetProcAddress(m_modulehandle, "zm_" #name "_init"          );\
        _pfn_##name##_block_size     = (pfn_##name##_block_size    )GetProcAddress(m_modulehandle, "zm_" #name "_block_size"    );\
        _pfn_##name##_ksize_min      = (pfn_##name##_ksize_min     )GetProcAddress(m_modulehandle, "zm_" #name "_ksize_min"     );\
        _pfn_##name##_ksize_max      = (pfn_##name##_ksize_max     )GetProcAddress(m_modulehandle, "zm_" #name "_ksize_max"     );\
        _pfn_##name##_ksize_multiple = (pfn_##name##_ksize_multiple)GetProcAddress(m_modulehandle, "zm_" #name "_ksize_multiple");\
        _pfn_##name##_set_ekey       = (pfn_##name##_set_ekey      )GetProcAddress(m_modulehandle, "zm_" #name "_set_ekey"      );\
        _pfn_##name##_set_dkey       = (pfn_##name##_set_dkey      )GetProcAddress(m_modulehandle, "zm_" #name "_set_dkey"      );\
        _pfn_##name##_enc_block      = (pfn_##name##_enc_block     )GetProcAddress(m_modulehandle, "zm_" #name "_enc_block"     );\
        _pfn_##name##_dec_block      = (pfn_##name##_dec_block     )GetProcAddress(m_modulehandle, "zm_" #name "_dec_block"     );

    #define BLOCKCIPHER_POINTER_IMPL(name)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new(void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        void sdk::zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx);\
            }\
        }\
        int32_t sdk::zm_##name##_block_size(void)\
        {\
            if (_pfn_##name##_block_size){\
                return _pfn_##name##_block_size();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_ksize_min(void)\
        {\
            if (_pfn_##name##_ksize_min){\
                return _pfn_##name##_ksize_min();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_ksize_max(void)\
        {\
            if (_pfn_##name##_ksize_max){\
                return _pfn_##name##_ksize_max();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_ksize_multiple(void)\
        {\
            if (_pfn_##name##_ksize_multiple){\
                return _pfn_##name##_ksize_multiple();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_set_ekey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            if (_pfn_##name##_set_ekey){\
                return _pfn_##name##_set_ekey(ctx, key, ksize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_set_dkey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            if (_pfn_##name##_set_dkey){\
                return _pfn_##name##_set_dkey(ctx, key, ksize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        void sdk::zm_##name##_enc_block(CONTEXT_TYPE_PTR(name) ctx, uint8_t* plaintext, uint8_t* ciphertext)\
        {\
            if (_pfn_##name##_enc_block){\
                _pfn_##name##_enc_block(ctx, plaintext, ciphertext);\
            }\
        }\
        void sdk::zm_##name##_dec_block(CONTEXT_TYPE_PTR(name) ctx, uint8_t* ciphertext, uint8_t* plaintext)\
        {\
            if (_pfn_##name##_dec_block){\
                _pfn_##name##_dec_block(ctx, ciphertext, plaintext);\
            }\
        }

    #define MAC_POINTER_DECLARA(name)\
        pfn_##name##_new          _pfn_##name##_new          = NULL;\
        pfn_##name##_free         _pfn_##name##_free         = NULL;\
        pfn_##name##_init         _pfn_##name##_init         = NULL;\
        pfn_##name##_starts       _pfn_##name##_starts       = NULL;\
        pfn_##name##_update       _pfn_##name##_update       = NULL;\
        pfn_##name##_final        _pfn_##name##_final        = NULL;\
        pfn_##name##_digest_size  _pfn_##name##_digest_size  = NULL;

    #define MAC_POINTER_LOAD(name)\
        _pfn_##name##_new           = (pfn_##name##_new          )GetProcAddress(m_modulehandle, "zm_" #name "_new"          );\
        _pfn_##name##_free          = (pfn_##name##_free         )GetProcAddress(m_modulehandle, "zm_" #name "_free"         );\
        _pfn_##name##_init          = (pfn_##name##_init         )GetProcAddress(m_modulehandle, "zm_" #name "_init"         );\
        _pfn_##name##_starts        = (pfn_##name##_starts       )GetProcAddress(m_modulehandle, "zm_" #name "_starts"       );\
        _pfn_##name##_update        = (pfn_##name##_update       )GetProcAddress(m_modulehandle, "zm_" #name "_update"       );\
        _pfn_##name##_final         = (pfn_##name##_final        )GetProcAddress(m_modulehandle, "zm_" #name "_final"        );\
        _pfn_##name##_digest_size   = (pfn_##name##_digest_size  )GetProcAddress(m_modulehandle, "zm_" #name "_digest_size"  );

    #define MAC_POINTER_IMPL(name, param, args)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new (void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        void sdk::zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx, param)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx, args);\
            }\
        }\
        zmerror sdk::zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t klen)\
        {\
            if (_pfn_##name##_starts){\
                return _pfn_##name##_starts(ctx, key, klen);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        void sdk::zm_##name##_update(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen)\
        {\
            if (_pfn_##name##_update){\
                _pfn_##name##_update(ctx, data, dlen);\
            }\
        }\
        void sdk::zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
            if (_pfn_##name##_final){\
                _pfn_##name##_final(ctx, output);\
            }\
        }\
        int32_t sdk::zm_##name##_digest_size(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_digest_size){\
                return _pfn_##name##_digest_size(ctx);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }

    #define CIPHER_MODE_POINTER_DECLARA(name)\
        pfn_##name##_new        _pfn_##name##_new      = NULL;\
        pfn_##name##_free       _pfn_##name##_free     = NULL;\
        pfn_##name##_init       _pfn_##name##_init     = NULL;\
        pfn_##name##_set_ekey   _pfn_##name##_set_ekey = NULL;\
        pfn_##name##_set_dkey   _pfn_##name##_set_dkey = NULL;\
        pfn_##name##_enc        _pfn_##name##_enc      = NULL;\
        pfn_##name##_dec        _pfn_##name##_dec      = NULL;

    #define CIPHER_MODE_POINTER_LOAD(name)\
        _pfn_##name##_new      = (pfn_##name##_new     )GetProcAddress(m_modulehandle, "zm_" #name "_new"       );\
        _pfn_##name##_free     = (pfn_##name##_free    )GetProcAddress(m_modulehandle, "zm_" #name "_free"      );\
        _pfn_##name##_init     = (pfn_##name##_init    )GetProcAddress(m_modulehandle, "zm_" #name "_init"      );\
        _pfn_##name##_set_ekey = (pfn_##name##_set_ekey)GetProcAddress(m_modulehandle, "zm_" #name "_set_ekey"  );\
        _pfn_##name##_set_dkey = (pfn_##name##_set_dkey)GetProcAddress(m_modulehandle, "zm_" #name "_set_dkey"  );\
        _pfn_##name##_enc      = (pfn_##name##_enc     )GetProcAddress(m_modulehandle, "zm_" #name "_enc"       );\
        _pfn_##name##_dec      = (pfn_##name##_dec     )GetProcAddress(m_modulehandle, "zm_" #name "_dec"       );

    #define CIPHER_MODE_POINTER_IMPL(name, param, args)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new (void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        void sdk::zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx, param)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx, args);\
            }\
        }\
        zmerror sdk::zm_##name##_set_ekey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            if (_pfn_##name##_set_ekey){\
                return _pfn_##name##_set_ekey(ctx, key, ksize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_set_dkey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            if (_pfn_##name##_set_dkey){\
                return _pfn_##name##_set_dkey(ctx, key, ksize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_enc (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            if (_pfn_##name##_enc){\
                return _pfn_##name##_enc(ctx, input, ilen, output);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_dec (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            if (_pfn_##name##_dec){\
                return _pfn_##name##_dec(ctx, input, ilen, output);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\

    #define CIPHER_MODE_WITH_IV_POINTER_IMPL(name, param, args)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new (void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        void sdk::zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx, param)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx, args);\
            }\
        }\
        zmerror sdk::zm_##name##_set_ekey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)\
        {\
            if (_pfn_##name##_set_ekey){\
                return _pfn_##name##_set_ekey(ctx, key, ksize, iv, ivsize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_set_dkey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)\
        {\
            if (_pfn_##name##_set_dkey){\
                return _pfn_##name##_set_dkey(ctx, key, ksize, iv, ivsize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_enc (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            if (_pfn_##name##_enc){\
                return _pfn_##name##_enc(ctx, input, ilen, output);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_dec (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            if (_pfn_##name##_dec){\
                return _pfn_##name##_dec(ctx, input, ilen, output);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }

     #define ADAE_POINTER_DECLARA(name)\
        pfn_##name##_new          _pfn_##name##_new          = NULL;\
        pfn_##name##_free         _pfn_##name##_free         = NULL;\
        pfn_##name##_init         _pfn_##name##_init         = NULL;\
        pfn_##name##_starts       _pfn_##name##_starts       = NULL;\
        pfn_##name##_update_aad   _pfn_##name##_update_aad   = NULL;\
        pfn_##name##_update_data  _pfn_##name##_update_data  = NULL;\
        pfn_##name##_final        _pfn_##name##_final        = NULL;

     #define AEAD_POINTER_LOAD(name)\
        _pfn_##name##_new         = (pfn_##name##_new        )GetProcAddress(m_modulehandle, "zm_" #name "_new"        );\
        _pfn_##name##_free        = (pfn_##name##_free       )GetProcAddress(m_modulehandle, "zm_" #name "_free"       );\
        _pfn_##name##_init        = (pfn_##name##_init       )GetProcAddress(m_modulehandle, "zm_" #name "_init"       );\
        _pfn_##name##_starts      = (pfn_##name##_starts     )GetProcAddress(m_modulehandle, "zm_" #name "_starts"     );\
        _pfn_##name##_update_aad  = (pfn_##name##_update_aad )GetProcAddress(m_modulehandle, "zm_" #name "_update_aad" );\
        _pfn_##name##_update_data = (pfn_##name##_update_data)GetProcAddress(m_modulehandle, "zm_" #name "_update_data");\
        _pfn_##name##_final       = (pfn_##name##_final      )GetProcAddress(m_modulehandle, "zm_" #name "_final"      );

     #define AEAD_POINTER_IMPL(name, cipher_param, cipher_args, starts_param, starts_args)\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new (void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        void sdk::zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx, cipher_param)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx, cipher_args);\
            }\
        }\
        zmerror sdk::zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx, starts_param)\
        {\
            if (_pfn_##name##_starts){\
                return _pfn_##name##_starts(ctx, starts_args);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_update_aad(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen)\
        {\
            if (_pfn_##name##_update_aad) { \
                return _pfn_##name##_update_aad(ctx, data, dlen); \
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_update_data(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen, uint8_t *output)\
        {\
            if (_pfn_##name##_update_data) { \
                return _pfn_##name##_update_data(ctx, data, dlen, output); \
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output)\
        {\
            if (_pfn_##name##_final) { \
                return _pfn_##name##_final(ctx, output); \
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }

    #define STREAMCIPHER_POINTER_DECLARA(name)\
        pfn_##name##_ksize_min        _pfn_##name##_ksize_min      = NULL; \
        pfn_##name##_ksize_max        _pfn_##name##_ksize_max      = NULL; \
        pfn_##name##_ksize_multiple   _pfn_##name##_ksize_multiple = NULL; \
        pfn_##name##_new              _pfn_##name##_new            = NULL; \
        pfn_##name##_free             _pfn_##name##_free           = NULL; \
        pfn_##name##_init             _pfn_##name##_init           = NULL; \
        pfn_##name##_set_ekey         _pfn_##name##_set_ekey       = NULL; \
        pfn_##name##_set_dkey         _pfn_##name##_set_dkey       = NULL; \
        pfn_##name##_encrypt          _pfn_##name##_encrypt        = NULL; \
        pfn_##name##_decrypt          _pfn_##name##_decrypt        = NULL; \

    #define STREAMCIPHER_WITH_IV_POINTER_DECLARA(name)\
        pfn_##name##_set_iv           _pfn_##name##_set_iv         = NULL;

    #define STREAMCIPHER_POINTER_LOAD(name)\
        _pfn_##name##_ksize_min      = (pfn_##name##_ksize_min     )GetProcAddress(m_modulehandle, "zm_" #name "_ksize_min"     ); \
        _pfn_##name##_ksize_max      = (pfn_##name##_ksize_max     )GetProcAddress(m_modulehandle, "zm_" #name "_ksize_max"     ); \
        _pfn_##name##_ksize_multiple = (pfn_##name##_ksize_multiple)GetProcAddress(m_modulehandle, "zm_" #name "_ksize_multiple"); \
        _pfn_##name##_new            = (pfn_##name##_new           )GetProcAddress(m_modulehandle, "zm_" #name "_new"           ); \
        _pfn_##name##_free           = (pfn_##name##_free          )GetProcAddress(m_modulehandle, "zm_" #name "_free"          ); \
        _pfn_##name##_init           = (pfn_##name##_init          )GetProcAddress(m_modulehandle, "zm_" #name "_init"          ); \
        _pfn_##name##_set_ekey       = (pfn_##name##_set_ekey      )GetProcAddress(m_modulehandle, "zm_" #name "_set_ekey"      ); \
        _pfn_##name##_set_dkey       = (pfn_##name##_set_dkey      )GetProcAddress(m_modulehandle, "zm_" #name "_set_dkey"      ); \
        _pfn_##name##_encrypt        = (pfn_##name##_encrypt       )GetProcAddress(m_modulehandle, "zm_" #name "_encrypt"       ); \
        _pfn_##name##_decrypt        = (pfn_##name##_decrypt       )GetProcAddress(m_modulehandle, "zm_" #name "_decrypt"       ); \

    #define STREAMCIPHER_WITH_IV_POINTER_LOAD(name)\
        _pfn_##name##_set_iv         = (pfn_##name##_set_iv        )GetProcAddress(m_modulehandle, "zm_" #name "_set_iv"        );

    #define STREAMCIPHER_POINTER_IMPL(name)\
        int32_t sdk::zm_##name##_ksize_min (void)\
        {\
            if (_pfn_##name##_ksize_min){\
                return _pfn_##name##_ksize_min();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_ksize_max (void)\
        {\
            if (_pfn_##name##_ksize_max){\
                return _pfn_##name##_ksize_max();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        int32_t sdk::zm_##name##_ksize_multiple (void)\
        {\
            if (_pfn_##name##_ksize_multiple){\
                return _pfn_##name##_ksize_multiple();\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        CONTEXT_TYPE_PTR(name) sdk::zm_##name##_new (void)\
        {\
            if (_pfn_##name##_new){\
                return _pfn_##name##_new();\
            }\
            return NULL;\
        }\
        void sdk::zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_free){\
                _pfn_##name##_free(ctx);\
            }\
        }\
        void sdk::zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx)\
        {\
            if (_pfn_##name##_init){\
                _pfn_##name##_init(ctx);\
            }\
        }\
        zmerror sdk::zm_##name##_set_ekey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            if (_pfn_##name##_set_ekey){\
                return _pfn_##name##_set_ekey(ctx, key, ksize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        zmerror sdk::zm_##name##_set_dkey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize)\
        {\
            if (_pfn_##name##_set_dkey){\
                return _pfn_##name##_set_dkey(ctx, key, ksize);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }\
        void sdk::zm_##name##_encrypt(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            if (_pfn_##name##_encrypt){\
                _pfn_##name##_encrypt(ctx, input, ilen, output);\
            }\
        }\
        void sdk::zm_##name##_decrypt(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output)\
        {\
            if (_pfn_##name##_decrypt){\
                _pfn_##name##_decrypt(ctx, input, ilen, output);\
            }\
        }\

    #define STREAMCIPHER_WITH_IV_POINTER_IMPL(name)\
        zmerror sdk::zm_##name##_set_iv(CONTEXT_TYPE_PTR(name) ctx, uint8_t* iv){\
            if (_pfn_##name##_set_dkey){\
                return _pfn_##name##_set_iv(ctx, iv);\
            }\
            return ZMCRYPTO_ERR_NULL_PTR;\
        }

    #if defined ZMCRYPTO_ALGO_BASE64
        BINTXT_POINTER_DECLARA(base64)
        BINTXT_POINTER_IMPL(base64)
    #endif

    #if defined ZMCRYPTO_ALGO_ADLER32
        CHECKSUM_POINTER_DECLARA(adler32)
        CHECKSUM_POINTER_IMPL(adler32)
    #endif

    #if defined ZMCRYPTO_ALGO_CRC32
        CHECKSUM_POINTER_DECLARA(crc32)
        CHECKSUM_POINTER_IMPL(crc32)
    #endif

    #if defined ZMCRYPTO_ALGO_MD5
        HASH_POINTER_DECLARA(md5)
        HASH_POINTER_IMPL(md5)
    #endif
    
    #if defined ZMCRYPTO_ALGO_SHA1
        HASH_POINTER_DECLARA(sha1)
        HASH_POINTER_IMPL(sha1)
    #endif

    #if defined ZMCRYPTO_ALGO_AES
        BLOCKCIPHER_POINTER_DECLARA(aes)
        BLOCKCIPHER_POINTER_IMPL(aes)
    #endif

    #if defined ZMCRYPTO_ALGO_DES
        BLOCKCIPHER_POINTER_DECLARA(des)
        BLOCKCIPHER_POINTER_IMPL(des)
    #endif

    #if defined ZMCRYPTO_ALGO_BLOWFISH
        BLOCKCIPHER_POINTER_DECLARA(blowfish)
        BLOCKCIPHER_POINTER_IMPL(blowfish)
    #endif

    #if defined ZMCRYPTO_ALGO_TWOFISH
        BLOCKCIPHER_POINTER_DECLARA(twofish)
        BLOCKCIPHER_POINTER_IMPL(twofish)
    #endif

    #if defined ZMCRYPTO_ALGO_TEA
        BLOCKCIPHER_POINTER_DECLARA(tea)
        BLOCKCIPHER_POINTER_IMPL(tea)
    #endif

    #if defined ZMCRYPTO_ALGO_XTEA
        BLOCKCIPHER_POINTER_DECLARA(xtea)
        BLOCKCIPHER_POINTER_IMPL(xtea)
    #endif

    #if defined ZMCRYPTO_ALGO_SM4
        BLOCKCIPHER_POINTER_DECLARA(sm4)
        BLOCKCIPHER_POINTER_IMPL(sm4)
    #endif

    #if defined ZMCRYPTO_ALGO_HMAC
        MAC_POINTER_DECLARA(hmac)
        MAC_POINTER_IMPL(hmac, HMAC_INIT_PARAM, HMAC_INIT_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_CMAC
        MAC_POINTER_DECLARA(cmac)
        MAC_POINTER_IMPL(cmac, CMAC_INIT_PARAM, CMAC_INIT_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_ECB
        CIPHER_MODE_POINTER_DECLARA(ecb)
        CIPHER_MODE_POINTER_IMPL(ecb, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_CBC
        CIPHER_MODE_POINTER_DECLARA(cbc)
        CIPHER_MODE_WITH_IV_POINTER_IMPL(cbc, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS)
    #endif
    
    #if defined ZMCRYPTO_ALGO_CFB
        CIPHER_MODE_POINTER_DECLARA(cfb)
        CIPHER_MODE_WITH_IV_POINTER_IMPL(cfb, CIPHER_MODE_INIT_PARAM_2, CIPHER_MODE_INIT_ARGS_2)
    #endif
    
    #if defined ZMCRYPTO_ALGO_OFB
        CIPHER_MODE_POINTER_DECLARA(ofb)
        CIPHER_MODE_WITH_IV_POINTER_IMPL(ofb, CIPHER_MODE_INIT_PARAM_2, CIPHER_MODE_INIT_ARGS_2)
    #endif
    
    #if defined ZMCRYPTO_ALGO_CTR
        CIPHER_MODE_POINTER_DECLARA(ctr)
        CIPHER_MODE_WITH_IV_POINTER_IMPL(ctr, CIPHER_MODE_INIT_PARAM_2, CIPHER_MODE_INIT_ARGS_2)
    #endif

    #if defined ZMCRYPTO_ALGO_CCM
        ADAE_POINTER_DECLARA(ccm)
        AEAD_POINTER_IMPL(ccm, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS, CCM_STARTS_PARAM, CCM_STARTS_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_GCM
        ADAE_POINTER_DECLARA(gcm)
        AEAD_POINTER_IMPL(gcm, CIPHER_MODE_INIT_PARAM, CIPHER_MODE_INIT_ARGS, GCM_STARTS_PARAM, GCM_STARTS_ARGS)
    #endif

    #if defined ZMCRYPTO_ALGO_RC4
        STREAMCIPHER_POINTER_DECLARA(rc4)
        STREAMCIPHER_POINTER_IMPL(rc4)
    #endif

    #if defined ZMCRYPTO_ALGO_SALSA20
        STREAMCIPHER_POINTER_DECLARA(salsa20)
        STREAMCIPHER_WITH_IV_POINTER_DECLARA(salsa20)
        STREAMCIPHER_POINTER_DECLARA(xsalsa20)
        STREAMCIPHER_WITH_IV_POINTER_DECLARA(xsalsa20)
    #endif

#if defined __linux__
        void* sdk::m_modulehandle = NULL;
#elif defined _WIN32
        HMODULE sdk::m_modulehandle = NULL;
#endif
        int32_t sdk::m_ref = 0;

    sdk::sdk(void)
    {
        #if defined __linux__
            //m_modulefile = "/vendor/zhangluduo/zmcrypto/build/linux/libzmcrypto.so";
            m_modulefile = "./libzmcrypto.so";
        #elif defined _WIN32
            m_modulefile = "./zmcrypto.dll";
        #endif

        if (m_ref++ == 0){
            load_library();
        }
    }
    sdk::~sdk(void)
    {
        if (--m_ref <= 0){
            if (m_modulehandle)
            {
                #if defined __linux__
                    dlclose(m_modulehandle);
                #elif defined _WIN32
                    ::FreeLibrary((HMODULE)m_modulehandle);
                #endif
                m_modulehandle = NULL;
            }
        }
    }
    void sdk::load_library(void)
    {
        if (m_modulehandle){
            return;
        }

        #if defined __linux__
            m_modulehandle = dlopen(m_modulefile, RTLD_LAZY);
        #elif defined _WIN32
            m_modulehandle = LoadLibraryA(m_modulefile);
        #endif

        if (!m_modulehandle){
            printf("Load module failed: %s\r\n", m_modulefile);

            #if defined __linux__
                printf ("%s\n", dlerror());
            #endif
            return;
        }

        _pfn_version_num   = (pfn_version_num  )GetProcAddress(m_modulehandle, "zm_version_num" );
        _pfn_version_str   = (pfn_version_str  )GetProcAddress(m_modulehandle, "zm_version_str" );
        _pfn_error_str     = (pfn_error_str    )GetProcAddress(m_modulehandle, "zm_error_str"   );
        _pfn_replace_fnc   = (pfn_replace_fnc  )GetProcAddress(m_modulehandle, "zm_replace_fnc" );

        #if defined ZMCRYPTO_ALGO_PBKDF2
            _pfn_pbkdf2 = (pfn_pbkdf2)GetProcAddress(m_modulehandle, "zm_pbkdf2");
        #endif
        #if defined ZMCRYPTO_ALGO_BLOCKPAD
            _pfn_blockpad_zero        = (pfn_blockpad_zero      )GetProcAddress(m_modulehandle, "zm_blockpad_zero"      );
            _pfn_blockpad_iso10126    = (pfn_blockpad_iso10126  )GetProcAddress(m_modulehandle, "zm_blockpad_iso10126"  );
            _pfn_blockpad_ansix923    = (pfn_blockpad_ansix923  )GetProcAddress(m_modulehandle, "zm_blockpad_ansix923"  );
            _pfn_blockpad_pkcs7       = (pfn_blockpad_pkcs7     )GetProcAddress(m_modulehandle, "zm_blockpad_pkcs7"     );

            _pfn_blockdepad_zero      = (pfn_blockdepad_zero    )GetProcAddress(m_modulehandle, "zm_blockdepad_zero"    );
            _pfn_blockdepad_iso10126  = (pfn_blockdepad_iso10126)GetProcAddress(m_modulehandle, "zm_blockdepad_iso10126");
            _pfn_blockdepad_ansix923  = (pfn_blockdepad_ansix923)GetProcAddress(m_modulehandle, "zm_blockdepad_ansix923");
            _pfn_blockdepad_pkcs7     = (pfn_blockdepad_pkcs7   )GetProcAddress(m_modulehandle, "zm_blockdepad_pkcs7"   );
        #endif

        #if defined ZMCRYPTO_ALGO_BASE64
            BINTXT_POINTER_LOAD(base64)
        #endif

        #if defined ZMCRYPTO_ALGO_ADLER32
            CHECKSUM_POINTER_LOAD(adler32)
        #endif

        #if defined ZMCRYPTO_ALGO_CRC32
            CHECKSUM_POINTER_LOAD(crc32)
        #endif

        #if defined ZMCRYPTO_ALGO_MD5
            HASH_POINTER_LOAD(md5)
        #endif

        #if defined ZMCRYPTO_ALGO_SHA1
            HASH_POINTER_LOAD(sha1)
        #endif

        #if defined ZMCRYPTO_ALGO_AES
            BLOCKCIPHER_POINTER_LOAD(aes)
        #endif

        #if defined ZMCRYPTO_ALGO_DES
            BLOCKCIPHER_POINTER_LOAD(des)
        #endif

        #if defined ZMCRYPTO_ALGO_BLOWFISH
            BLOCKCIPHER_POINTER_LOAD(blowfish)
        #endif

        #if defined ZMCRYPTO_ALGO_TWOFISH
            BLOCKCIPHER_POINTER_LOAD(twofish)
        #endif

        #if defined ZMCRYPTO_ALGO_TEA
            BLOCKCIPHER_POINTER_LOAD(tea)
        #endif

        #if defined ZMCRYPTO_ALGO_XTEA
            BLOCKCIPHER_POINTER_LOAD(xtea)
        #endif

        #if defined ZMCRYPTO_ALGO_SM4
            BLOCKCIPHER_POINTER_LOAD(sm4)
        #endif

        #if defined ZMCRYPTO_ALGO_HMAC
            MAC_POINTER_LOAD(hmac)
        #endif

        #if defined ZMCRYPTO_ALGO_CMAC
           MAC_POINTER_LOAD(cmac)
        #endif

        #if defined ZMCRYPTO_ALGO_ECB
            CIPHER_MODE_POINTER_LOAD(ecb)
        #endif

        #if defined ZMCRYPTO_ALGO_CBC
            CIPHER_MODE_POINTER_LOAD(cbc)
        #endif
        
        #if defined ZMCRYPTO_ALGO_CFB
            CIPHER_MODE_POINTER_LOAD(cfb)
        #endif
        
        #if defined ZMCRYPTO_ALGO_OFB
            CIPHER_MODE_POINTER_LOAD(ofb)
        #endif
        
        #if defined ZMCRYPTO_ALGO_CTR
            CIPHER_MODE_POINTER_LOAD(ctr)
        #endif

        #if defined ZMCRYPTO_ALGO_CCM
            AEAD_POINTER_LOAD(ccm)
        #endif

        #if defined ZMCRYPTO_ALGO_GCM
            AEAD_POINTER_LOAD(gcm)
        #endif

        #if defined ZMCRYPTO_ALGO_RC4
            STREAMCIPHER_POINTER_LOAD(rc4)
        #endif

        #if defined ZMCRYPTO_ALGO_SALSA20
            STREAMCIPHER_POINTER_LOAD(salsa20)
            STREAMCIPHER_WITH_IV_POINTER_LOAD(salsa20)
            STREAMCIPHER_POINTER_LOAD(xsalsa20)
            STREAMCIPHER_WITH_IV_POINTER_LOAD(xsalsa20)
        #endif
    }

    uint32_t sdk::zm_version_num(void)
    {
        if (_pfn_version_num){
            return _pfn_version_num();
        }
        return 0;
    }
    const char* sdk::zm_version_str(void)
    {
        if (_pfn_version_str){
            return _pfn_version_str();
        }
        return NULL;
    }
    const char* sdk::zm_error_str(int32_t code)
    {
        if (_pfn_error_str){
            return _pfn_error_str(code);
        }
        return NULL;
    }
    const void* sdk::zm_replace_fnc(const char* fname, void* pfn)
    {
        if (_pfn_replace_fnc)
        {
            return _pfn_replace_fnc(fname, pfn);
        }
        return NULL;
    }
} /* namespace zmcrypto */
