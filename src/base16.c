
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
 *   Date: Mar. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "base16.h"

#if defined ZMCRYPTO_ALGO_BASE16

    zmerror base16_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        uint16_t hi = (uint16_t)(options >> 16);         /* How much characters one line */
        uint16_t lo = (uint16_t)(options & 0x000000ff);  /* table index */

        if (lo != 0 && lo != 1) { return ZMCRYPTO_ERR_OVERFLOW; }

        static const char *alphabets[2] = 
        {
            "0123456789ABCDEF",
            "0123456789abcdef",
        };

        const char *alphabet = alphabets[lo];
        uint32_t dlen = ilen * 2;

        if (hi > 0) { dlen += (dlen / hi); }

        if (!output)
        {
            *olen = dlen;
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        if (*olen < dlen)
            { return ZMCRYPTO_ERR_OVERFLOW; }

        uint32_t x = 0;
        uint32_t line = 0;
        for (uint32_t i = 0; i < ilen; i++) 
        {
            output[x++] = alphabet[input[i] >> 4 & 0x0f]; if (hi > 0 && ++line >= hi) { output[x++] = '\n'; line = 0; }
            output[x++] = alphabet[input[i]      & 0x0f]; if (hi > 0 && ++line >= hi) { output[x++] = '\n'; line = 0; }
        }

        *olen = dlen;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror base16_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        static const unsigned char map[] = 
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
            0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 89:;<=>? */
            0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, /* @ABCDEFG */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* HIJKLMNO */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* PQRSTUVW */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* XYZ[\]^_ */
            0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, /* `abcdefg */
        };

        uint16_t hi = (uint16_t)(options >> 16);         /* skip whitespace(0x0d, 0x0a, 0x20, 0x09) */
        uint16_t lo = (uint16_t)(options & 0x000000ff);  /* table index */

        if (lo != 0 && lo != 1) { return ZMCRYPTO_ERR_OVERFLOW; }

        if (!output)
        {
            *olen = (ilen + 1) / 2;
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        /* check the output sizes */
        if (*olen < (ilen + 1) / 2)
            { return ZMCRYPTO_ERR_OVERFLOW; }

        uint32_t x = 0;
        uint8_t idx0 = 0;
        uint8_t idx1 = 0;
        uint8_t inchar[2] = {0, 0};
        uint8_t inindex = 0x00;

        while (ilen--)
        {
            // Skip whitespace
            if ((hi == 1) && (*input == '\r' || *input == '\n' || *input == '\t' || *input == 0x20))
            {
                input++;
                continue;
            }
            inchar[inindex] = *input;

            if (inindex == 0x01)
            {
                if ((inchar[0] < '0') || (inchar[0] > 'g') || (inchar[1] < '0') || (inchar[1] > 'g')) 
                    { return ZMCRYPTO_ERR_INVALID_CHAR; }

                idx0 = (unsigned char) (inchar[0] & 0x1F) ^ 0x10;
                idx1 = (unsigned char) (inchar[1] & 0x1F) ^ 0x10;

                if (map[idx0] == 0xff || map[idx1] == 0xff) 
                    { return ZMCRYPTO_ERR_INVALID_CHAR; }

                output[x] = (unsigned char) (map[idx0] << 4) | map[idx1];
                x++;
            } /* end */

            inindex = ~inindex & 0x01;
            input++;
        }
        *olen = x;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif
