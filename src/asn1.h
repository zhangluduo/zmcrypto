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
 *   Date: Sep 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_ASN1_H
#define ZMCRYPTO_ASN1_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_TOOL_ASN1

        /**
         * These constants comply with the DER encoded ASN.1 type tags.
         * DER encoding uses hexadecimal representation.
         * An example DER sequence is:\n
         * - 0x02 -- tag indicating INTEGER
         * - 0x01 -- length in octets
         * - 0x05 -- value
         */
        #define ASN1_TAG_BOOLEAN                 0x01U
        #define ASN1_TAG_INTEGER                 0x02U
        #define ASN1_TAG_BIT_STRING              0x03U
        #define ASN1_TAG_OCTET_STRING            0x04U
        #define ASN1_TAG_NULL                    0x05U
        #define ASN1_TAG_OID                     0x06U
        #define ASN1_TAG_ENUMERATED              0x0AU
        #define ASN1_TAG_UTF8_STRING             0x0CU
        #define ASN1_TAG_SEQUENCE                0x10U
        #define ASN1_TAG_SET                     0x11U
        #define ASN1_TAG_PRINTABLE_STRING        0x13U
        #define ASN1_TAG_T61_STRING              0x14U
        #define ASN1_TAG_IA5_STRING              0x16U
        #define ASN1_TAG_UTC_TIME                0x17U
        #define ASN1_TAG_GENERALIZED_TIME        0x18U
        #define ASN1_TAG_UNIVERSAL_STRING        0x1CU
        #define ASN1_TAG_BMP_STRING              0x1EU
        #define ASN1_TAG_PRIMITIVE               0x00U
        #define ASN1_TAG_CONSTRUCTED             0x20U
        #define ASN1_TAG_CONTEXT_SPECIFIC        0x80U

        /*
        * Bit masks for each of the components of an ASN.1 tag as specified in
        * ITU X.690 (08/2015), section 8.1 "General rules for encoding",
        * paragraph 8.1.2.2:
        *
        * Bit  8     7   6   5          1  
        *     +-------+-----+------------+ 
        *     | Class | P/C | Tag number | 
        *     +-------+-----+------------+ 
        */
        #define MBEDTLS_ASN1_TAG_CLASS_MASK          0xC0
        #define MBEDTLS_ASN1_TAG_PC_MASK             0x20
        #define MBEDTLS_ASN1_TAG_VALUE_MASK          0x1F

    #endif /* ZMCRYPTO_TOOL_ASN1 */

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_ASN1_H */
