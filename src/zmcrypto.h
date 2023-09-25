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

#if !defined ZMCRYPTO_H
#define ZMCRYPTO_H

#include "zmconfig.h"

#if defined __linux__
  #if !defined API
    #define API 
    //__attribute__ ((visibility("default")))
  #endif
#elif defined _WIN32
  #if !defined API
    #if defined DLL_IMPORTS
      #define API _declspec(dllimport)
    #else /* DLL_EXPORTS */
      #define API _declspec(dllexport)
    #endif
  #endif
#endif

#define ZM_VALSTR_STRUCT(x) { x, #x }

#if !defined CONTEXT_TYPE_PTR
    #define CONTEXT_TYPE_PTR(name) struct name##_ctx*
#endif

/*
example: 
#define ZMCRYPTO_VERSION_NUM    0x01020304
#define ZMCRYPTO_VERSION_STR    "ZmCrypto 1.2.3.4"
*/

#define ZMCRYPTO_VERSION_NUM    0x00010000
#define ZMCRYPTO_VERSION_STR    "ZmCrypto 0.1.0.0"

#ifdef __cplusplus
extern "C" {
#endif

    API const uint32_t zm_version_num(void);
    API const char* zm_version_str(void);
    API const char* zm_error_str(int32_t code);
    API const void* zm_replace_fnc(const char* fname, void* pfn);
    typedef uint32_t (*pfn_version_num)(void);
    typedef const char* (*pfn_version_str)(void);
    typedef const char* (*pfn_error_str)(int32_t code);
    typedef const void* (*pfn_replace_fnc)(const char* fname, void* pfn);
    typedef const void* (*pfn_spy_fnc)(const char* fname, void* pfn);

    #if defined ZMCRYPTO_ALGO_PBKDF2
      API zmerror zm_pbkdf2 (
              void*   (*hash_new)         (void),
              void    (*hash_free)        (void* ctx),
              int32_t (*hash_digest_size) (void),
              int32_t (*hash_block_size)  (void),
              void    (*hash_init)        (void* ctx),
              void    (*hash_starts)      (void* ctx),
              void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dlen),
              void    (*hash_final)       (void* ctx, uint8_t* output),
          uint8_t* p, uint32_t plen, uint8_t* s, uint32_t slen, uint32_t c, uint8_t* dk, uint32_t dklen);
      typedef zmerror (*pfn_pbkdf2) (
              void*   (*hash_new)         (void),
              void    (*hash_free)        (void* ctx),
              int32_t (*hash_digest_size) (void),
              int32_t (*hash_block_size)  (void),
              void    (*hash_init)        (void* ctx),
              void    (*hash_starts)      (void* ctx),
              void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dlen),
              void    (*hash_final)       (void* ctx, uint8_t* output),
          uint8_t* p, uint32_t plen, uint8_t* s, uint32_t slen, uint32_t c, uint8_t* dk, uint32_t dklen);
    #endif

    #if defined ZMCRYPTO_ALGO_BLOCKPAD
      API zmerror zm_blockpad_zero (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);
      API zmerror zm_blockpad_iso10126 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen, void (*rng_get_bytes) (uint8_t* data, uint32_t dlen));
      API zmerror zm_blockpad_ansix923 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);
      API zmerror zm_blockpad_pkcs7 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);

      API zmerror zm_blockdepad_zero(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
      API zmerror zm_blockdepad_iso10126(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
      API zmerror zm_blockdepad_ansix923(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
      API zmerror zm_blockdepad_pkcs7(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);

      typedef zmerror (*pfn_blockpad_zero) (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);
      typedef zmerror (*pfn_blockpad_iso10126) (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen, void (*rng_get_bytes) (uint8_t* data, uint32_t dlen));
      typedef zmerror (*pfn_blockpad_ansix923) (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);
      typedef zmerror (*pfn_blockpad_pkcs7) (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);

      typedef zmerror (*pfn_blockdepad_zero)(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
      typedef zmerror (*pfn_blockdepad_iso10126)(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
      typedef zmerror (*pfn_blockdepad_ansix923)(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
      typedef zmerror (*pfn_blockdepad_pkcs7)(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
    #endif

    /**
     * Binary to Text Encoders and Decoders
     */
    #define BINTXT_FUNCTION_DECLARA(name)\
        API zmerror zm_##name##_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options);\
        API zmerror zm_##name##_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options);\
        typedef zmerror (*pfn_##name##_encode)(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options);\
        typedef zmerror (*pfn_##name##_decode)(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options);

    /**
     * Non-Cryptographic Checksums
     */

    #define CHECKSUM_FUNCTION_DECLARA(name)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new(void);\
        API void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx);\
        API int32_t zm_##name##_checksum_size(void);\
        API void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_starts(CONTEXT_TYPE_PTR(name));\
        API void zm_##name##_update(CONTEXT_TYPE_PTR(name), uint8_t* data, uint32_t dlen);\
        API void zm_##name##_final(CONTEXT_TYPE_PTR(name), uint8_t* output);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new)(void);\
        typedef void (*pfn_##name##_free)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef int32_t (*pfn_##name##_checksum_size)(void);\
        typedef void (*pfn_##name##_init)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_starts)(CONTEXT_TYPE_PTR(name));\
        typedef void (*pfn_##name##_update)(CONTEXT_TYPE_PTR(name), uint8_t* data, uint32_t dlen);\
        typedef void (*pfn_##name##_final)(CONTEXT_TYPE_PTR(name), uint8_t* output);

    /**
     * Hash functions
     */

    #define HASH_FUNCTION_DECLARA(name)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new(void);\
        API void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx);\
        API int32_t zm_##name##_digest_size(void);\
        API int32_t zm_##name##_block_size(void);\
        API void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_update(CONTEXT_TYPE_PTR(name), uint8_t* data, uint32_t dlen);\
        API void zm_##name##_final(CONTEXT_TYPE_PTR(name), uint8_t* output);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new)(void);\
        typedef void (*pfn_##name##_free)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef int32_t (*pfn_##name##_digest_size)(void);\
        typedef int32_t (*pfn_##name##_block_size)(void);\
        typedef void (*pfn_##name##_init)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_starts)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_update)(CONTEXT_TYPE_PTR(name), uint8_t* data, uint32_t dlen);\
        typedef void (*pfn_##name##_final)(CONTEXT_TYPE_PTR(name), uint8_t* output);

    /**
     * Block cipher functions
     */

    #define BLOCKCIPHER_FUNCTION_DECLARA(name)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new(void);\
        API void zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx);\
        API int32_t zm_##name##_block_size(void);\
        API int32_t zm_##name##_ksize_min(void);\
        API int32_t zm_##name##_ksize_max(void);\
        API int32_t zm_##name##_ksize_multiple(void);\
        API zmerror zm_##name##_set_ekey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        API zmerror zm_##name##_set_dkey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        API void zm_##name##_enc_block(CONTEXT_TYPE_PTR(name) ctx, uint8_t* plaintext, uint8_t* ciphertext);\
        API void zm_##name##_dec_block(CONTEXT_TYPE_PTR(name) ctx, uint8_t* ciphertext, uint8_t* plaintext);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new)(void);\
        typedef void (*pfn_##name##_free)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_init)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef int32_t (*pfn_##name##_block_size)(void);\
        typedef int32_t (*pfn_##name##_ksize_min)(void);\
        typedef int32_t (*pfn_##name##_ksize_max)(void);\
        typedef int32_t (*pfn_##name##_ksize_multiple)(void);\
        typedef zmerror (*pfn_##name##_set_ekey)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        typedef zmerror (*pfn_##name##_set_dkey)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        typedef void (*pfn_##name##_enc_block)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* plaintext, uint8_t* ciphertext);\
        typedef void (*pfn_##name##_dec_block)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* ciphertext, uint8_t* plaintext);

    /**
     * Stream cipher functions
     */

    #define STREAMCIPHER_FUNCTION_DECLARA(name)\
        API int32_t zm_##name##_ksize_min (void);\
        API int32_t zm_##name##_ksize_max (void);\
        API int32_t zm_##name##_ksize_multiple (void);\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new (void);\
        API void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx);\
        API zmerror zm_##name##_set_ekey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        API zmerror zm_##name##_set_dkey(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        API void zm_##name##_encrypt(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        API void zm_##name##_decrypt(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        typedef int32_t (*pfn_##name##_ksize_min) (void);\
        typedef int32_t (*pfn_##name##_ksize_max) (void);\
        typedef int32_t (*pfn_##name##_ksize_multiple) (void);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new) (void);\
        typedef void (*pfn_##name##_free )(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_init )(CONTEXT_TYPE_PTR(name) ctx);\
        typedef zmerror (*pfn_##name##_set_ekey)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        typedef zmerror (*pfn_##name##_set_dkey)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        typedef void (*pfn_##name##_encrypt)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        typedef void (*pfn_##name##_decrypt)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);

    #define STREAMCIPHER_WITH_IV_FUNCTION_DECLARA(name)\
        API zmerror zm_##name##_set_iv(CONTEXT_TYPE_PTR(name) ctx, uint8_t* iv);\
        typedef zmerror (*pfn_##name##_set_iv)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* iv);

    /**
     * MAC function
     */

    #define HMAC_INIT_PARAM\
        void*   (*hash_new)         (void),\
        void    (*hash_free)        (void* ctx),\
        int32_t (*hash_digest_size) (void),\
        int32_t (*hash_block_size)  (void),\
        void    (*hash_init)        (void* ctx),\
        void    (*hash_starts)      (void* ctx),\
        void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dlen),\
        void    (*hash_final)       (void* ctx, uint8_t* output)

    #define HMAC_INIT_ARGS\
        hash_new,\
        hash_free,\
        hash_digest_size,\
        hash_block_size,\
        hash_init,\
        hash_starts,\
        hash_update,\
        hash_final
    
    #define CMAC_INIT_PARAM\
        void*   (*cipher_new)            (void),\
        void    (*cipher_free)           (void* ctx),\
        void    (*cipher_init)           (void* ctx),\
        int32_t (*cipher_block_size)     (void),\
        int32_t (*cipher_ksize_min)      (void),\
        int32_t (*cipher_ksize_max)      (void),\
        int32_t (*cipher_ksize_multiple) (void),\
        int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),\
        int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize),\
        void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext),\
        void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext)

    #define CMAC_INIT_ARGS\
        cipher_new,\
        cipher_free,\
        cipher_init,\
        cipher_block_size,\
        cipher_ksize_min,\
        cipher_ksize_max,\
        cipher_ksize_multiple,\
        cipher_set_ekey,\
        cipher_set_dkey,\
        cipher_enc_block,\
        cipher_dec_block

    #define MAC_FUNCTION_DECLARA(name, param)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new (void);\
        API void    zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx);\
        API void    zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx, param);\
        API void    zm_##name##_reset(CONTEXT_TYPE_PTR(name) ctx);\
        API zmerror zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t klen);\
        API void    zm_##name##_update(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen);\
        API void    zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output);\
        API int32_t zm_##name##_digest_size(CONTEXT_TYPE_PTR(name) ctx);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new) (void);\
        typedef void    (*pfn_##name##_free)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void    (*pfn_##name##_init)(CONTEXT_TYPE_PTR(name) ctx, param);\
        typedef void    (*pfn_##name##_reset)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef zmerror (*pfn_##name##_starts)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t klen);\
        typedef void    (*pfn_##name##_update)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen);\
        typedef void    (*pfn_##name##_final)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output);\
        typedef int32_t (*pfn_##name##_digest_size)(CONTEXT_TYPE_PTR(name) ctx);

    #define CIPHER_MODE_INIT_PARAM\
        void*   (*cipher_new)            (void),\
        void    (*cipher_free)           (void* ctx),\
        void    (*cipher_init)           (void* ctx),\
        int32_t (*cipher_block_size)     (void),\
        int32_t (*cipher_ksize_min)      (void),\
        int32_t (*cipher_ksize_max)      (void),\
        int32_t (*cipher_ksize_multiple) (void),\
        int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),\
        int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize),\
        void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext),\
        void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext)

    #define CIPHER_MODE_INIT_PARAM_2\
        void*   (*cipher_new)            (void),\
        void    (*cipher_free)           (void* ctx),\
        void    (*cipher_init)           (void* ctx),\
        int32_t (*cipher_block_size)     (void),\
        int32_t (*cipher_ksize_min)      (void),\
        int32_t (*cipher_ksize_max)      (void),\
        int32_t (*cipher_ksize_multiple) (void),\
        int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),\
        void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)

    #define CIPHER_MODE_INIT_ARGS\
        cipher_new,\
        cipher_free,\
        cipher_init,\
        cipher_block_size,\
        cipher_ksize_min,\
        cipher_ksize_max,\
        cipher_ksize_multiple,\
        cipher_set_ekey,\
        cipher_set_dkey,\
        cipher_enc_block,\
        cipher_dec_block

    #define CIPHER_MODE_INIT_ARGS_2\
        cipher_new,\
        cipher_free,\
        cipher_init,\
        cipher_block_size,\
        cipher_ksize_min,\
        cipher_ksize_max,\
        cipher_ksize_multiple,\
        cipher_set_ekey,\
        cipher_enc_block

    #define CIPHER_MODE_FUNCTION_DECLARA(name, param)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new (void);\
        API void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx, param);\
        API zmerror zm_##name##_set_ekey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        API zmerror zm_##name##_set_dkey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        API zmerror zm_##name##_enc (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        API zmerror zm_##name##_dec (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new) (void);\
        typedef void (*pfn_##name##_free) (CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_init) (CONTEXT_TYPE_PTR(name) ctx, param);\
        typedef zmerror (*pfn_##name##_set_ekey) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        typedef zmerror (*pfn_##name##_set_dkey) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize);\
        typedef zmerror (*pfn_##name##_enc) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        typedef zmerror (*pfn_##name##_dec) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);

    #define CIPHER_MODE_WITH_IV_FUNCTION_DECLARA(name, param)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new (void);\
        API void zm_##name##_free (CONTEXT_TYPE_PTR(name) ctx);\
        API void zm_##name##_init (CONTEXT_TYPE_PTR(name) ctx, param);\
        API zmerror zm_##name##_set_ekey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize);\
        API zmerror zm_##name##_enc (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new) (void);\
        typedef void (*pfn_##name##_free) (CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_init) (CONTEXT_TYPE_PTR(name) ctx, param);\
        typedef zmerror (*pfn_##name##_set_ekey) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize);\
        typedef zmerror (*pfn_##name##_enc) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);

    #define CIPHER_MODE_WITH_IV_FUNCTION_DECLARA_2(name, param)\
        API zmerror zm_##name##_set_dkey (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize);\
        API zmerror zm_##name##_dec (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);\
        typedef zmerror (*pfn_##name##_set_dkey) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize);\
        typedef zmerror (*pfn_##name##_dec) (CONTEXT_TYPE_PTR(name) ctx, uint8_t* input, uint32_t ilen, uint8_t* output);

    #define CCM_STARTS_PARAM \
            uint8_t *key, uint32_t klen, uint8_t *nonce, uint32_t noncelen,\
            uint64_t datalen, uint64_t aadlen, uint32_t taglen, uint32_t direction

    #define CCM_STARTS_ARGS \
            key, klen, nonce, noncelen, datalen, aadlen, taglen, direction

    #define GCM_STARTS_PARAM \
            uint8_t *key, uint32_t klen, uint8_t *iv, uint32_t ivlen, uint32_t direction

    #define GCM_STARTS_ARGS \
            key, klen, iv, ivlen, direction

    #define AEAD_FUNCTION_DECLARA(name, cipher_param, starts_param)\
        API CONTEXT_TYPE_PTR(name) zm_##name##_new (void);\
        API void    zm_##name##_free(CONTEXT_TYPE_PTR(name) ctx);\
        API void    zm_##name##_init(CONTEXT_TYPE_PTR(name) ctx, cipher_param);\
        API zmerror zm_##name##_starts(CONTEXT_TYPE_PTR(name) ctx, starts_param);\
        API zmerror zm_##name##_update_aad(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen);\
        API zmerror zm_##name##_update_data(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen, uint8_t *output);\
        API zmerror zm_##name##_final(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new) (void);\
        typedef void    (*pfn_##name##_free)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void    (*pfn_##name##_init)(CONTEXT_TYPE_PTR(name) ctx, cipher_param);\
        typedef zmerror (*pfn_##name##_starts)(CONTEXT_TYPE_PTR(name) ctx, starts_param);\
        typedef zmerror (*pfn_##name##_update_aad)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen);\
        typedef zmerror (*pfn_##name##_update_data)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* data, uint32_t dlen, uint8_t *output);\
        typedef zmerror (*pfn_##name##_final)(CONTEXT_TYPE_PTR(name) ctx, uint8_t* output);

    #if defined ZMCRYPTO_ALGO_CCM
        AEAD_FUNCTION_DECLARA(ccm, CIPHER_MODE_INIT_PARAM, CCM_STARTS_PARAM)
    #endif

    #if defined ZMCRYPTO_ALGO_GCM
        AEAD_FUNCTION_DECLARA(gcm, CIPHER_MODE_INIT_PARAM, GCM_STARTS_PARAM)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE64
        BINTXT_FUNCTION_DECLARA(base64)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE58
        BINTXT_FUNCTION_DECLARA(base58)
    #endif

    #if defined ZMCRYPTO_ALGO_BASE32
        BINTXT_FUNCTION_DECLARA(base32)
    #endif

    #if defined ZMCRYPTO_ALGO_ADLER32
        CHECKSUM_FUNCTION_DECLARA(adler32)
    #endif

    #if defined ZMCRYPTO_ALGO_CRC32
        CHECKSUM_FUNCTION_DECLARA(crc32)
    #endif

    #if defined ZMCRYPTO_ALGO_MD5
        HASH_FUNCTION_DECLARA(md5)
    #endif
   
    #if defined ZMCRYPTO_ALGO_AES
        BLOCKCIPHER_FUNCTION_DECLARA(aes)
    #endif

    #if defined ZMCRYPTO_ALGO_BLOWFISH
        BLOCKCIPHER_FUNCTION_DECLARA(blowfish)
    #endif

    #if defined ZMCRYPTO_ALGO_DES
        BLOCKCIPHER_FUNCTION_DECLARA(des)
    #endif

    #if defined ZMCRYPTO_ALGO_TEA
        BLOCKCIPHER_FUNCTION_DECLARA(tea)
    #endif

    #if defined ZMCRYPTO_ALGO_XTEA
        BLOCKCIPHER_FUNCTION_DECLARA(xtea)
    #endif

    #if defined ZMCRYPTO_ALGO_TWOFISH
        BLOCKCIPHER_FUNCTION_DECLARA(twofish)
    #endif

    #if defined ZMCRYPTO_ALGO_SM4
        BLOCKCIPHER_FUNCTION_DECLARA(sm4)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA1
        HASH_FUNCTION_DECLARA(sha1)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA2
        HASH_FUNCTION_DECLARA(sha224)
        HASH_FUNCTION_DECLARA(sha256)
        HASH_FUNCTION_DECLARA(sha384)
        HASH_FUNCTION_DECLARA(sha512)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA3
        HASH_FUNCTION_DECLARA(sha3_224)
        HASH_FUNCTION_DECLARA(sha3_256)
        HASH_FUNCTION_DECLARA(sha3_384)
        HASH_FUNCTION_DECLARA(sha3_512)
    #endif

    #if defined ZMCRYPTO_ALGO_SM3
        HASH_FUNCTION_DECLARA(sm3)
    #endif

    #if defined ZMCRYPTO_ALGO_HMAC
        MAC_FUNCTION_DECLARA(hmac, HMAC_INIT_PARAM)
    #endif

    #if defined ZMCRYPTO_ALGO_CMAC
        MAC_FUNCTION_DECLARA(cmac, CMAC_INIT_PARAM)
    #endif

    #if defined ZMCRYPTO_ALGO_ECB
       CIPHER_MODE_FUNCTION_DECLARA(ecb, CIPHER_MODE_INIT_PARAM)
    #endif

    #if defined ZMCRYPTO_ALGO_CBC
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA(cbc, CIPHER_MODE_INIT_PARAM)
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA_2(cbc, CIPHER_MODE_INIT_PARAM)
   #endif
    
    #if defined ZMCRYPTO_ALGO_CFB
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA(cfb, CIPHER_MODE_INIT_PARAM_2)
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA_2(cfb, CIPHER_MODE_INIT_PARAM_2)
    #endif
    
    #if defined ZMCRYPTO_ALGO_OFB
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA(ofb, CIPHER_MODE_INIT_PARAM_2)
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA_2(ofb, CIPHER_MODE_INIT_PARAM_2)
    #endif
    
    #if defined ZMCRYPTO_ALGO_CTR
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA(ctr, CIPHER_MODE_INIT_PARAM_2)
        CIPHER_MODE_WITH_IV_FUNCTION_DECLARA_2(ctr, CIPHER_MODE_INIT_PARAM_2)
    #endif

    #if defined ZMCRYPTO_ALGO_RC4
        STREAMCIPHER_FUNCTION_DECLARA(rc4)
    #endif

    #if defined ZMCRYPTO_ALGO_SALSA20
        STREAMCIPHER_FUNCTION_DECLARA(salsa20)
        STREAMCIPHER_WITH_IV_FUNCTION_DECLARA(salsa20)
        STREAMCIPHER_FUNCTION_DECLARA(xsalsa20)
        STREAMCIPHER_WITH_IV_FUNCTION_DECLARA(xsalsa20)
    #endif

#ifdef __cplusplus
}
#endif
#endif /* ZMCRYPTO_H */
