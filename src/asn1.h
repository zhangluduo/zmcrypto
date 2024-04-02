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
 *   Date: Oct. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/*
NOTE:
    This tool is parsed according to the DET format.
*/

#if !defined ZMCRYPTO_ASN1_H
#define ZMCRYPTO_ASN1_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_TOOL_ASN1

        struct asn1_data;
        struct asn1_ctx;

        struct asn1_ctx* asn1_ctx_new();

        void asn1_ctx_free(struct asn1_ctx* ctx);

        void asn1_ctx_init(struct asn1_ctx* ctx);

        uint8_t* asn1_get_tag_data   (struct asn1_ctx* ctx); /* return ctx->tag.data; */
        uint8_t* asn1_get_length_data(struct asn1_ctx* ctx); /* return ctx->length.data; */
        uint8_t* asn1_get_value_data (struct asn1_ctx* ctx); /* return ctx->value.data; */
        uint8_t* asn1_get_next_data  (struct asn1_ctx* ctx); /* return ctx->next.data; */
        uint32_t asn1_get_tag_dlen   (struct asn1_ctx* ctx); /* return ctx->tag.dlen; */
        uint32_t asn1_get_length_dlen(struct asn1_ctx* ctx); /* return ctx->length.dlen; */
        uint32_t asn1_get_value_dlen (struct asn1_ctx* ctx); /* return ctx->value.dlen; */
        uint32_t asn1_get_next_dlen  (struct asn1_ctx* ctx); /* return ctx->next.dlen; */

        /*
        param:
            data: 
                Input asn1 DER format encoded data
            dlen: 
                size of data in bytes
            ctx:  
                output raw data of tag, length and value. If the input 'data'
                contains the next tlv, then ctx->next points to the next element
                parse position.
            copy: 
                If this value set to 1, then copy next parse position of point 
                'data' to 'next' buffer and the caller can be free 'data'. 
                However, doing so will increase the number of memory allocations 
                and affect efficiency.

                If this value set to 0, during this process, malloc will not 
                be called inside the function for memory allocation, so it 
                is necessary to ensure the validity of the data during the 
                life cycle.
        return:
            ZMCRYPTO_ERR_SUCCESSED for parse succeed, or other code when error occurs.
        */
        zmerror asn1_parse_data(uint8_t* data, uint32_t dlen, struct asn1_ctx* ctx, uint32_t copy);

        zmerror asn1_encode_length(uint32_t in, uint8_t* out, uint32_t* olen);
        zmerror asn1_decode_length(uint8_t* in, uint32_t* ilen, uint32_t* out);
        zmerror asn1_encode_boolean(zmbool in, uint8_t* out, uint32_t* olen);
        zmerror asn1_decode_boolean(uint8_t* in, uint32_t ilen, zmbool* out);
        zmerror asn1_encode_object_identifier(uint32_t* in, uint32_t ilen, uint8_t* out, uint32_t* olen);
        zmerror asn1_decode_object_identifier(uint8_t* in, uint32_t ilen, uint32_t* out, uint32_t* olen);

        /* returns ZMCRYPTO_ERR_SUCCESSED or ZMCRYPTO_ERR_INVALID_ASN1_TAG */
        zmerror asn1_is_tag_sequence(uint8_t tag);
        zmerror asn1_is_tag_set(uint8_t tag);
        zmerror asn1_is_tag_boolean(uint8_t tag);
        zmerror asn1_is_tag_integer(uint8_t tag);
        zmerror asn1_is_tag_null(uint8_t tag);
        zmerror asn1_is_tag_object_identifier(uint8_t tag);
        zmerror asn1_is_tag_object_descriptor(uint8_t tag);
        zmerror asn1_is_tag_external(uint8_t tag);
        zmerror asn1_is_tag_real(uint8_t tag);
        zmerror asn1_is_tag_enumerated(uint8_t tag);
        zmerror asn1_is_tag_embedded_pdv(uint8_t tag);
        zmerror asn1_is_tag_utc_time(uint8_t tag);
        zmerror asn1_is_tag_generalized_time(uint8_t tag);
        zmerror asn1_is_tag_octet_string(uint8_t tag);
        zmerror asn1_is_tag_utf8_string(uint8_t tag);
        zmerror asn1_is_tag_bit_string(uint8_t tag);
        zmerror asn1_is_tag_numeric_string(uint8_t tag);
        zmerror asn1_is_tag_printable_string(uint8_t tag);
        zmerror asn1_is_tag_t61_string(uint8_t tag);
        zmerror asn1_is_tag_ia5_string(uint8_t tag);
        zmerror asn1_is_tag_graphic_string(uint8_t tag);
        zmerror asn1_is_tag_visible_string(uint8_t tag);
        zmerror asn1_is_tag_general_string(uint8_t tag);
        zmerror asn1_is_tag_universal_string(uint8_t tag);
        zmerror asn1_is_tag_bmp_string(uint8_t tag);

        /* result is 0 for primitive tag, result is 1 for constructed tag*/
        zmerror asn1_is_tag_constructed(uint8_t tag, zmbool* result);

        /* debug funcions */
        const char* asn1_debug_tag_to_string(uint8_t tag);

    #endif /* ZMCRYPTO_TOOL_ASN1 */

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_ASN1_H */
