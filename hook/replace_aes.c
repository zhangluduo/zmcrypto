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

 /**
 * Reference: 
 *     [Announcing the ADVANCED ENCRYPTION STANDARD (AES)]
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 */

#include "replace_aes.h"

extern pfn_aes_new             _orig_aes_new            ; 
extern pfn_aes_free            _orig_aes_free           ; 
extern pfn_aes_init            _orig_aes_init           ; 
extern pfn_aes_block_size      _orig_aes_block_size     ; 
extern pfn_aes_ksize_min       _orig_aes_ksize_min      ; 
extern pfn_aes_ksize_max       _orig_aes_ksize_max      ; 
extern pfn_aes_ksize_multiple  _orig_aes_ksize_multiple ; 
extern pfn_aes_set_ekey        _orig_aes_set_ekey       ; 
extern pfn_aes_set_dkey        _orig_aes_set_dkey       ; 
extern pfn_aes_enc_block       _orig_aes_enc_block      ; 
extern pfn_aes_dec_block       _orig_aes_dec_block      ; 

void print_data(char* title, uint8_t* data, uint32_t dlen){
    printf ("%s", title);
    for (uint32_t i = 0; i < dlen; i++){
        printf("%02x ", data[i]);
    }
}

struct aes_ctx* hook_aes_new(void)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);

    if (_orig_aes_new){
       return _orig_aes_new();
    }

    return NULL;
}

void hook_aes_free (struct aes_ctx* ctx)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);

    if (_orig_aes_free){
       _orig_aes_free(ctx);
    }
}

void hook_aes_init (struct aes_ctx* ctx)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);

    if (_orig_aes_init){
       _orig_aes_init(ctx);
    }
}

int32_t hook_aes_block_size (void)
{ 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    if (_orig_aes_block_size){
        return _orig_aes_block_size();
    }
    return ZMCRYPTO_ERR_NULL_PTR; 
}

int32_t hook_aes_ksize_min (void)
{ 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    if (_orig_aes_ksize_min){
        return _orig_aes_ksize_min();
    }
    return ZMCRYPTO_ERR_NULL_PTR; 
}

int32_t hook_aes_ksize_max (void)
{ 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    if (_orig_aes_ksize_max){
        return _orig_aes_ksize_max();
    }
    return ZMCRYPTO_ERR_NULL_PTR; 
}

int32_t hook_aes_ksize_multiple (void)
{ 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    if (_orig_aes_ksize_multiple){
        return _orig_aes_ksize_multiple();
    }
    return ZMCRYPTO_ERR_NULL_PTR; 
}

int32_t hook_aes_set_ekey (struct aes_ctx* ctx, uint8_t* key, uint32_t ksize)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);

    if (_orig_aes_set_ekey){
       return _orig_aes_set_ekey(ctx, key, ksize);
    }

    return ZMCRYPTO_ERR_NULL_PTR;
}

zmerror hook_aes_set_dkey (struct aes_ctx* ctx, uint8_t* key, uint32_t ksize)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);

    if (_orig_aes_set_dkey){
       return _orig_aes_set_dkey(ctx, key, ksize);
    }

    return ZMCRYPTO_ERR_NULL_PTR;
}

void hook_aes_enc_block (struct aes_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    print_data("plaintext: ", plaintext, 16);
    printf ("\n");

    if (_orig_aes_enc_block){
       _orig_aes_enc_block(ctx, plaintext, ciphertext);
    }
}

void hook_aes_dec_block (struct aes_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    print_data("ciphertext: ", ciphertext, 16);
    printf ("\n");

    if (_orig_aes_dec_block){
       _orig_aes_dec_block(ctx, ciphertext, plaintext);
    }
}
