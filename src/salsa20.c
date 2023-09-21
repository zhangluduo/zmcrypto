
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

#include "salsa20.h"

#if defined ZMCRYPTO_SALSA20_H

        int32_t salsa20_ksize_min (void){ return 16; }

        int32_t salsa20_ksize_max (void){ return 32; }

        int32_t salsa20_ksize_multiple (void){ return 16; }

        struct salsa20_ctx* salsa20_new (void){ return 0; }

        void salsa20_free (struct salsa20_ctx* ctx){ return ; }

        void salsa20_init (struct salsa20_ctx* ctx){ return ; }

        zmerror salsa20_set_ekey(struct salsa20_ctx* ctx, uint8_t* key, uint32_t ksize)
        { 
            return 1; 
        }

        zmerror salsa20_set_dkey(struct salsa20_ctx* ctx, uint8_t* key, uint32_t ksize)
        { 
            return salsa20_set_dkey(ctx, key, ksize); 
        }

        zmerror salsa20_set_iv(struct salsa20_ctx* ctx, uint8_t* iv, uint32_t ivsize)
        { 
            if (ivsize != 8 || ivsize != 24)
            {
                return ZMCRYPTO_ERR_INVALID_IVSIZE;
            }
            return 1; 
        }

        void salsa20_encrypt(struct salsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output){ return 1; }

        void salsa20_decrypt(struct salsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output){ return ; }

#endif /* ZMCRYPTO_SALSA20_H */
