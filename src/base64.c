
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

#include "base64.h"

#if defined ZMCRYPTO_ALGO_BASE64

    static const char * const base64_enc_codes[] = {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" };

    static const uint8_t base64_dec_codes[2][128] =
    {
        {
            0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,    62,  0xff,  0xff,  0xff,    63,
              52,    53,    54,    55,    56,    57,    58,    59,    60,    61,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,     0,     1,     2,     3,     4,     5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
              15,    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
              41,    42,    43,    44,    45,    46,    47,    48,    49,    50,    51,  0xff,  0xff,  0xff,  0xff,  0xff,
        },
        {
            0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  62,  0xff,  0xff,
              52,    53,    54,    55,    56,    57,    58,    59,    60,    61,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,
            0xff,     0,     1,     2,     3,     4,     5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
              15,    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,  0xff,  0xff,  0xff,  0xff,    63,
            0xff,    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
              41,    42,    43,    44,    45,    46,    47,    48,    49,    50,    51,  0xff,  0xff,  0xff,  0xff,  0xff,
        }
    };

    zmerror base64_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        uint16_t hi = (uint16_t)(options >> 16);         /* How much characters one line */
        uint16_t lo = (uint16_t)(options & 0x000000ff);  /* table index */

        if (lo != 0 && lo != 1) { return ZMCRYPTO_ERR_OVERFLOW; }

        uint32_t dlen = (ilen << 3) / 6;
        switch ((ilen << 3) - (dlen * 6))
        {
            case  2: dlen += 3; break;
            case  4: dlen += 2; break;
            default: break;
        }

        if (hi > 0) { dlen += (dlen / hi); }

        if (*olen < dlen + 1 || !output)
        {
            *olen = dlen + 1;
            return ZMCRYPTO_ERR_OVERFLOW;
        }

        uint32_t chars = 0;
        uint32_t i = 0;
        uint8_t C1, C2, C3;
        uint8_t* p = output;
        uint32_t n = ilen / 3 * 3;

        for (i = 0; i < n; i += 3)
        {
            C1 = *input++;
            C2 = *input++;
            C3 = *input++;

            *p++ = base64_enc_codes[lo][(C1 >> 2) & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
            *p++ = base64_enc_codes[lo][(((C1 &  3) << 4) + (C2 >> 4)) & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
            *p++ = base64_enc_codes[lo][(((C2 & 15) << 2) + (C3 >> 6)) & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
            *p++ = base64_enc_codes[lo][C3 & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
        }

        if (i < ilen)
        {
            C1 = *input++;
            C2 = ((i + 1) < ilen) ? *input++ : 0;
            *p++ = base64_enc_codes[lo][(C1 >> 2) & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
            *p++ = base64_enc_codes[lo][(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }

            if ((i + 1) < ilen)
            {
                *p++ = base64_enc_codes[lo][((C2 & 15) << 2) & 0x3F]; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
            }
            else
            {
                *p++ = '='; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
            }

            *p++ = '='; if (++chars >= hi && hi > 0) { *p++ = 0x0a; chars = 0; }
        }
        *olen = p - output;
        *p = 0;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror base64_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        uint16_t hi = (uint16_t)(options >> 16);         /* skip whitespace(0x0d, 0x0a, 0x20, 0x09) */
        uint16_t lo = (uint16_t)(options & 0x000000ff);  /* table index */

        if (lo != 0 && lo != 1) { return ZMCRYPTO_ERR_OVERFLOW; }

        if (!output)
        {
            *olen = ilen;
            return ZMCRYPTO_ERR_OVERFLOW;
        }

        uint32_t n = 0;
        uint8_t *p = output;
        uint32_t x, j, i;

        for (j = 3, x = 0, i = 0; i < ilen; i++, input++)
        {
            if (*input == 0x0d || *input == 0x0a || *input == 0x20 || *input == 0x09)
            {
                if (!hi) { return ZMCRYPTO_ERR_INVALID_CHAR; }
                continue;
            }

            if (*input == '=')
            {
                if (!((ilen >= 1 && i == ilen - 1) || (ilen >= 2 && i == ilen - 2))) { return ZMCRYPTO_ERR_INVALID_CHAR; }
                j -= 1;
            }
            else
            {
                if (base64_dec_codes[lo][*input] == (uint8_t)-1) { return ZMCRYPTO_ERR_INVALID_CHAR; }
            }

            x  = (x << 6) | (base64_dec_codes[lo][*input] & 0x3F);
            if (++n == 4)
            {
                n = 0;
                if (j > 0) *p++ = (uint8_t)(x >> 16);
                if (j > 1) *p++ = (uint8_t)(x >>  8);
                if (j > 2) *p++ = (uint8_t)(x      );
            }
        }
        *olen = p - output;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif