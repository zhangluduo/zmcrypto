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

#if !defined CONTEXT_TYPE
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

    API uint32_t zm_version_num(void);
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
        API void zm_##name##_starts(CONTEXT_TYPE_PTR(name));\
        API void zm_##name##_update(CONTEXT_TYPE_PTR(name), uint8_t* data, uint32_t dlen);\
        API void zm_##name##_final(CONTEXT_TYPE_PTR(name), uint8_t* output);\
        typedef CONTEXT_TYPE_PTR(name) (*pfn_##name##_new)(void);\
        typedef void (*pfn_##name##_free)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef int32_t (*pfn_##name##_digest_size)(void);\
        typedef int32_t (*pfn_##name##_block_size)(void);\
        typedef void (*pfn_##name##_init)(CONTEXT_TYPE_PTR(name) ctx);\
        typedef void (*pfn_##name##_starts)(CONTEXT_TYPE_PTR(name));\
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


    #if defined ZMCRYPTO_ALGO_BASE64
        BINTXT_FUNCTION_DECLARA(base64)
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

    #if defined ZMCRYPTO_ALGO_DES
        BLOCKCIPHER_FUNCTION_DECLARA(des)
    #endif

    #if defined ZMCRYPTO_ALGO_SHA1
        HASH_FUNCTION_DECLARA(sha1)
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
    
#ifdef __cplusplus
}
#endif
#endif /* ZMCRYPTO_H */
