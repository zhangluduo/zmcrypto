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

/* 
   [GCM]         Dworkin, M., "Recommendation for Block Cipher Modes of
                 Operation: Galois/Counter Mode (GCM) and GMAC",
                 National Institute of Standards and Technology SP 800-
                 38D, November 2007.
*/


/*
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * See also:
 * [MGV] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * We use the algorithm described as Shoup's method with 4-bit tables in
 * [MGV] 4.1, pp. 12-13, to enhance speed without using too much memory.
 */

#include "gcm.h"

#if defined ZMCRYPTO_ALGO_GCM

   struct gcm_ctx
   {
      void*   (*cipher_new)            (void);
      void    (*cipher_free)           (void* ctx);
      void    (*cipher_init)           (void* ctx);
      int32_t (*cipher_block_size)     (void);
      int32_t (*cipher_ksize_min)      (void);
      int32_t (*cipher_ksize_max)      (void);
      int32_t (*cipher_ksize_multiple) (void);
      int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
      int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize);
      void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);
      void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext);
      void* cipher_ctx;
      /* other members */
   } ;

   struct gcm_ctx* gcm_new (void)
   {
      struct gcm_ctx* ctx = (struct gcm_ctx*)zmcrypto_malloc(sizeof(struct gcm_ctx));
      zmcrypto_memset(ctx, 0, sizeof(struct gcm_ctx));
      return ctx;
   }

   void gcm_free (struct gcm_ctx* ctx)
   {
      if (ctx)
      {
         if (ctx->cipher_ctx)
         {
            ctx->cipher_free(ctx->cipher_ctx);
            ctx->cipher_ctx = NULL;
         }
         zmcrypto_free (ctx);
      }
   }

   void gcm_init (
      struct gcm_ctx* ctx,
      void*   (*cipher_new)            (void),
      void    (*cipher_free)           (void* ctx),
      void    (*cipher_init)           (void* ctx),
      int32_t (*cipher_block_size)     (void),
      int32_t (*cipher_ksize_min)      (void),
      int32_t (*cipher_ksize_max)      (void),
      int32_t (*cipher_ksize_multiple) (void),
      int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
      int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize),
      void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext),
      void    (*cipher_dec_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
   )
   {
      ctx->cipher_new            = cipher_new            ;
      ctx->cipher_free           = cipher_free           ;
      ctx->cipher_init           = cipher_init           ;
      ctx->cipher_block_size     = cipher_block_size     ;
      ctx->cipher_ksize_min      = cipher_ksize_min      ;
      ctx->cipher_ksize_max      = cipher_ksize_max      ;
      ctx->cipher_ksize_multiple = cipher_ksize_multiple ;
      ctx->cipher_set_ekey       = cipher_set_ekey       ;
      ctx->cipher_set_dkey       = cipher_set_dkey       ;
      ctx->cipher_enc_block      = cipher_enc_block      ;
      ctx->cipher_dec_block      = cipher_dec_block      ;
      ctx->cipher_ctx = NULL;
   }

   zmerror gcm_starts (
      struct gcm_ctx* ctx,
      uint8_t *key, uint32_t klen,
      uint8_t *iv, uint32_t ivlen,
      uint32_t direction
   )
   {
      return ZMCRYPTO_ERR_SUCCESSED;
   }

   zmerror gcm_update_aad (
      struct gcm_ctx* ctx,
      uint8_t *aad,  
      uint32_t alen
   )
   {
      return ZMCRYPTO_ERR_SUCCESSED;
   }

   zmerror gcm_update_data (
      struct gcm_ctx* ctx,
      uint8_t *data, 
      uint32_t dlen, 
      uint8_t *output
   )
   {
      return ZMCRYPTO_ERR_SUCCESSED;
   }

   zmerror gcm_final (
      struct gcm_ctx* ctx,
      uint8_t *tag
   )
   {
      return ZMCRYPTO_ERR_SUCCESSED;
   }

#endif /* ZMCRYPTO_ALGO_GCM */
