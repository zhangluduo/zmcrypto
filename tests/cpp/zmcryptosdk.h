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
 *         https://github.com/zhangluduo/
 */

#include "../../src/zmconfig.h"
#include "../../src/zmcrypto.h"

#if defined __linux__
    #include <dlfcn.h>
#elif defined _WIN32
    #include <windows.h>
	#define dlsym GetProcAddress
#endif

#if !defined ZMCRYPTOSDK_H
#define ZMCRYPTOSDK_H

namespace zmcrypto
{
    class sdk
    {
    public:
        sdk(void);
        virtual ~sdk(void);
    
    private:
        void load_library(void);

    public:
        uint32_t zm_version_num(void);
        const char* zm_version_str(void);
        const char* zm_error_str(int32_t code);
        const void* zm_replace_fnc(const char* fname, void* pfn);

        #if defined ZMCRYPTO_ALGO_PBKDF2
        zmerror zm_pbkdf2 (
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
            zmerror zm_blockpad_zero (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);
            zmerror zm_blockpad_iso10126 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen, void (*rng_get_bytes) (uint8_t* data, uint32_t dlen));
            zmerror zm_blockpad_ansix923 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);
            zmerror zm_blockpad_pkcs7 (uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen);

            zmerror zm_blockdepad_zero(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
            zmerror zm_blockdepad_iso10126(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
            zmerror zm_blockdepad_ansix923(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
            zmerror zm_blockdepad_pkcs7(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen);
        #endif

        /**
         * Binary to Text Encoders and Decoders
         */
        #if defined ZMCRYPTO_ALGO_BASE16
            BINTXT_FUNCTION_DECLARA(base16)
        #endif
        
        #if defined ZMCRYPTO_ALGO_BASE64
            BINTXT_FUNCTION_DECLARA(base64)
        #endif

        /**
         * Non-Cryptographic Checksums
         */
        
        #if defined ZMCRYPTO_ALGO_ADLER32
            CHECKSUM_FUNCTION_DECLARA(adler32)
        #endif

        #if defined ZMCRYPTO_ALGO_CRC32
            CHECKSUM_FUNCTION_DECLARA(crc32)
        #endif

        /**
         * Hash functions
         */

        #if defined ZMCRYPTO_ALGO_MD5
            HASH_FUNCTION_DECLARA(md5)
        #endif

        #if defined ZMCRYPTO_ALGO_MD4
            HASH_FUNCTION_DECLARA(md4)
        #endif

        #if defined ZMCRYPTO_ALGO_MD2
            HASH_FUNCTION_DECLARA(md2)
        #endif

        #if defined ZMCRYPTO_ALGO_ED2K
            HASH_FUNCTION_DECLARA(ed2k)
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

        /**
         * Block cipher functions
         */

        #if defined ZMCRYPTO_ALGO_AES
            BLOCKCIPHER_FUNCTION_DECLARA(aes)
        #endif

        #if defined ZMCRYPTO_ALGO_DES
            BLOCKCIPHER_FUNCTION_DECLARA(des)
        #endif

        #if defined ZMCRYPTO_ALGO_BLOWFISH
            BLOCKCIPHER_FUNCTION_DECLARA(blowfish)
        #endif

        #if defined ZMCRYPTO_ALGO_TWOFISH
            BLOCKCIPHER_FUNCTION_DECLARA(twofish)
        #endif

        #if defined ZMCRYPTO_ALGO_TEA
            BLOCKCIPHER_FUNCTION_DECLARA(tea)
        #endif

        #if defined ZMCRYPTO_ALGO_XTEA
            BLOCKCIPHER_FUNCTION_DECLARA(xtea)
        #endif

        #if defined ZMCRYPTO_ALGO_SM4
            BLOCKCIPHER_FUNCTION_DECLARA(sm4)
        #endif

        /**
         * MAC functions
         */

        #if defined ZMCRYPTO_ALGO_HMAC
            MAC_FUNCTION_DECLARA(hmac, HMAC_INIT_PARAM)
        #endif

        #if defined ZMCRYPTO_ALGO_CMAC
            MAC_FUNCTION_DECLARA(cmac, CMAC_INIT_PARAM)
        #endif

        /**
         * Cipher mode functions
         */

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

        #if defined ZMCRYPTO_ALGO_CCM
            AEAD_FUNCTION_DECLARA(ccm, CIPHER_MODE_INIT_PARAM, CCM_STARTS_PARAM, CCM_FINAL_PARAM)
        #endif

        #if defined ZMCRYPTO_ALGO_GCM
            AEAD_FUNCTION_DECLARA(gcm, CIPHER_MODE_INIT_PARAM, GCM_STARTS_PARAM, GCM_FINAL_PARAM)
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

    //private:
    public:

        const char* m_modulefile;

        #if defined __linux__
            static void* m_modulehandle;
        #elif defined _WIN32
            static HMODULE m_modulehandle;
        #endif

        static int32_t m_ref;
    };
} /* namespace zmcrypto */
#endif /* ZMCRYPTOSDK_H */
