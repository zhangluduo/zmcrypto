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

#if !defined ZMCRYPTO_CRC3232_H
#define ZMCRYPTO_CRC3232_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_CRC32
        struct crc32_ctx;

        struct crc32_ctx* crc32_new (void);
        void crc32_free (struct crc32_ctx* ctx);
        int32_t crc32_checksum_size (void);
        void crc32_init (struct crc32_ctx* ctx);
        void crc32_starts (struct crc32_ctx* ctx);
        void crc32_update (struct crc32_ctx* ctx, uint8_t* data, uint32_t dlen);
        void crc32_final (struct crc32_ctx* ctx, uint8_t* output);
    #endif

    #ifdef DYNAMIC_CRC_TABLE
        extern uint32_t crc_table[];   /* crc table, defined below */
    #endif
    
#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_CRC3232_H */
