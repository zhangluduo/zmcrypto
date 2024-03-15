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
 *   Date: Oct 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/*
NOTE:
    This tool is parsed according to the DET format.
*/

#include "asn1.h"
#include "debug.h"

#if defined ZMCRYPTO_TOOL_ASN1

    /* private: */
        struct asn1_data
        {
            uint8_t* data;
            uint32_t dlen;
        };

    /* public: */
        struct asn1_ctx
        {
            struct asn1_data tag;
            struct asn1_data length;
            struct asn1_data value;
            struct asn1_data next;
            uint32_t copy;
        };

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
    #define ASN1_TAG_OBJECT_IDENTIFIER       0x06U
    #define ASN1_TAG_OBJECT_DESCRIPTOR       0x07U
    #define ASN1_TAG_EXTERNAL                0x08U
    #define ASN1_TAG_REAL                    0x09U
    #define ASN1_TAG_ENUMERATED              0x0AU
    #define ASN1_TAG_EMBEDDED_PDV            0x0BU /* Embedded Presentation Data Value */
    #define ASN1_TAG_UTF8_STRING             0x0CU
    #define ASN1_TAG_SEQUENCE                0x10U /* Sequence/sequence of */
    #define ASN1_TAG_SET                     0x11U /* Set/set of */
    #define ASN1_TAG_NUMERIC_STRING          0x12U
    #define ASN1_TAG_PRINTABLE_STRING        0x13U
    #define ASN1_TAG_T61_STRING              0x14U
    #define ASN1_TAG_IA5_STRING              0x16U
    #define ASN1_TAG_UTC_TIME                0x17U
    #define ASN1_TAG_GENERALIZED_TIME        0x18U
    #define ASN1_TAG_GRAPHIC_STRING          0x19U
    #define ASN1_TAG_VISIBLE_STRING          0x1AU
    #define ASN1_TAG_GENERAL_STRING          0x1BU
    #define ASN1_TAG_UNIVERSAL_STRING        0x1CU
    #define ASN1_TAG_BMP_STRING              0x1EU

    #define ASN1_TAG_EOC                     0x00U /* End-of-Content */

    /*
        Bit  8     7   6   5  4  3  2  1
            +-------+-----+------------+
            | Class | P/C | Tag number |
            +-------+-----+------------+
                       |
                       +--- 0 = primitive
                       |
                       +--- 1 = constructed        X.609(21)_F03

        +------------------------------------+
        | Class              | Bit 8 | Bit 7 |
        +------------------------------------+
        | Universal          |   0   |   0   |
        | Application        |   0   |   1   |
        | Context-specific   |   1   |   0   |
        | Private            |   1   |   1   |
        +------------------------------------+
    */

    #define ASN1_PC_PRIMITIVE                0x00U
    #define ASN1_PC_CONSTRUCTED              0x01U
    
    #define ASN1_MASK_CLASS                0xC0U /* 1100 0000 */
    #define ASN1_MASK_PC                   0x20U /* 0010 0000 */
    #define ASN1_MASK_VAL                  0x1FU /* 0001 1111 */
    #define ASN1_MASK_LEN                  0x7FU /* 0111 1111 */

    /* private begin */

    struct 
    {
        const int32_t val;
        const char* const str;
        int constructed; /*0=base type, 1=constructed type,2=both are possible*/
    } static const zm_tag_map[] = {
        {ASN1_TAG_BOOLEAN          , "BOOLEAN"         , 0},
        {ASN1_TAG_INTEGER          , "INTEGER"         , 0},
        {ASN1_TAG_BIT_STRING       , "BIT_STRING"      , 2},
        {ASN1_TAG_OCTET_STRING     , "OCTET_STRING"    , 2},
        {ASN1_TAG_NULL             , "NULL"            , 0},
        {ASN1_TAG_OBJECT_IDENTIFIER, "OBJECT_IDENTIFIE", 0},
        {ASN1_TAG_OBJECT_DESCRIPTOR, "OBJECT_DESCRIPTO", 2},
        {ASN1_TAG_EXTERNAL         , "EXTERNAL"        , 1},
        {ASN1_TAG_REAL             , "REAL"            , 0},
        {ASN1_TAG_ENUMERATED       , "ENUMERATED"      , 0},
        {ASN1_TAG_EMBEDDED_PDV     , "EMBEDDED_PDV"    , 1},
        {ASN1_TAG_UTF8_STRING      , "UTF8_STRING"     , 2},
        {ASN1_TAG_SEQUENCE         , "SEQUENCE"        , 1},
        {ASN1_TAG_SET              , "SET"             , 1},
        {ASN1_TAG_NUMERIC_STRING   , "NUMERIC_STRING"  , 2},
        {ASN1_TAG_PRINTABLE_STRING , "PRINTABLE_STRING", 2},
        {ASN1_TAG_T61_STRING       , "T61_STRING"      , 2},
        {ASN1_TAG_IA5_STRING       , "IA5_STRING"      , 2},
        {ASN1_TAG_UTC_TIME         , "UTC_TIME"        , 2},
        {ASN1_TAG_GENERALIZED_TIME , "GENERALIZED_TIME", 2},
        {ASN1_TAG_GRAPHIC_STRING   , "GRAPHIC_STRING"  , 2},
        {ASN1_TAG_VISIBLE_STRING   , "VISIBLE_STRING"  , 2},
        {ASN1_TAG_GENERAL_STRING   , "GENERAL_STRING"  , 2},
        {ASN1_TAG_UNIVERSAL_STRING , "UNIVERSAL_STRING", 2},
        {ASN1_TAG_BMP_STRING       , "BMP_STRING"      , 1},
    };

    zmerror is_valid_tag(uint8_t tag)
    {
        uint8_t _class = (tag & ASN1_MASK_CLASS) >> 6;
        uint8_t _pc = (tag & ASN1_MASK_PC) >> 5;
        uint8_t _tag_num = (tag & ASN1_MASK_VAL);

        for (int i = 0; i < sizeof(zm_tag_map) / sizeof(zm_tag_map[0]); i++){
            if (zm_tag_map[i].val == tag)
            {
                if (zm_tag_map[i].constructed == 1 || zm_tag_map[i].constructed == 2)
                {
                    return (_pc == 1 ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
                }
                break;
            }
        }

        return ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    /* private end */

    struct asn1_ctx* asn1_ctx_new()
    {
        struct asn1_ctx* ctx = (struct asn1_ctx*)zmcrypto_malloc(sizeof(struct asn1_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct asn1_ctx));
        return ctx;
    }

    void asn1_ctx_free(struct asn1_ctx* ctx)
    {
        if (ctx->copy)
        {
            if (ctx->tag.data)
                { zmcrypto_free(ctx->tag.data); ctx->tag.data = NULL; ctx->tag.dlen = 0; }
            if (ctx->length.data)
                { zmcrypto_free(ctx->length.data); ctx->length.data = NULL; ctx->length.dlen = 0; }
            if (ctx->value.data)
                { zmcrypto_free(ctx->value.data); ctx->value.data = NULL; ctx->value.dlen = 0; }
            if (ctx->next.data)
                { zmcrypto_free(ctx->next.data); ctx->next.data = NULL; ctx->next.dlen = 0; }
        }
        zmcrypto_free(ctx);
    }

    void asn1_ctx_init(struct asn1_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct asn1_ctx));
    }

    zmerror asn1_parse_data(uint8_t* data, uint32_t dlen, struct asn1_ctx* ctx, uint32_t copy)
    {
        //ZMCRYPTO_LOG("dlen: %d", dlen);

        if (dlen == 0)
        {
            ctx->tag.data = NULL;
            ctx->tag.dlen = 0;

            ctx->length.data = NULL;
            ctx->length.dlen = 0;

            ctx->value.data = NULL;
            ctx->value.dlen = 0;

            ctx->next.data = NULL;
            ctx->next.dlen = 0;

            return ZMCRYPTO_ERR_SUCCESSED;
        }

        uint8_t* start = data;
        uint8_t* end = data + (dlen - 1); /* Points to the last valid character */
        //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);

        uint8_t* tag_d = NULL;
        uint8_t* len_d = NULL;
        uint8_t* val_d = NULL;
        uint8_t* next_d = NULL;
        uint32_t tag_l = 0;
        uint32_t len_l = 0;
        uint32_t val_l = 0;
        uint32_t next_l = 0;

        uint32_t len_len = 0;

        tag_d = start;
        tag_l = 1;
        start++; /* skip tag */
        //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);

        if (start > end){
            //ZMCRYPTO_LOG("");
            return ZMCRYPTO_ERR_ASN1_OUT_OF_DATA;
        }

        len_d = start;
        if (!(*start & 0x80) /* 128 */)
        {
            len_l = 1;
            len_len = (uint32_t)(*start);
            start++; /* skip len data*/
            //ZMCRYPTO_LOG("len: %d", len_d[0]);
            //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);
        }
        else
        {
            uint32_t len_byte = ((*start) & ASN1_MASK_LEN);
            //ZMCRYPTO_LOG("len_byte: %d", len_byte);
            if (len_byte >= 1 && len_byte <= 4)
            { 
                if (end - start < (len_byte + 1)) 
                    { 
                        //ZMCRYPTO_LOG(""); 
                        return ZMCRYPTO_ERR_ASN1_INVALID_LEN; 
                    };

                len_l = len_byte + 1;

                if (len_byte == 1) 
                { 
                    len_len = start[1]; 
                    //ZMCRYPTO_LOG("len_len: %d", len_len);
                }
                else if (len_byte == 2) 
                { 
                    len_len = ((uint32_t)(*(start + 1)) << 8) | 
                        (uint32_t)(*(start + 2)); 
                    //ZMCRYPTO_LOG("len_len: %d", len_len);
                }
                else if (len_byte == 3) 
                { 
                    len_len = ((uint32_t)(*(start + 1)) << 16) | 
                        ((uint32_t)(*(start + 2)) << 8) | 
                        (uint32_t)(*(start + 3)); 
                    //ZMCRYPTO_LOG("len_len: %d", len_len);
                }
                else if (len_byte == 4) 
                { 
                    len_len = ((uint32_t)(*(start + 1)) << 24) | 
                        ((uint32_t)(*(start + 2)) << 16) | 
                        ((uint32_t)(*(start + 3)) << 8) | 
                        (uint32_t)(*(start + 4)); 
                    //ZMCRYPTO_LOG("len_len: %d", len_len);
                }

                start += len_l; /* skip len data */
                //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);
            }

            /* more then 4GB, don't implement it for now */
            else
            {
                //ZMCRYPTO_LOG(""); 
                return ZMCRYPTO_ERR_ASN1_INVALID_LEN; 
            }
        }

        val_d = start;
        val_l = len_len;
        start += len_len; /* skip value data */

        if ((start - 1) > end)
        {
            //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);
            return ZMCRYPTO_ERR_ASN1_OUT_OF_DATA;
        }
        else if ((start - 1) < end)
        {
            //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);
            next_d = start;
            next_l = end - (start - 1);
        }
        else
        {
            //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);
        }

        ctx->copy = copy;
        if (copy)
        {
            ctx->tag.data = zmcrypto_malloc(tag_l);
            ctx->tag.dlen = tag_l;
            zmcrypto_memcpy(ctx->tag.data, tag_d, tag_l);

            ctx->length.data = zmcrypto_malloc(len_l);
            ctx->length.dlen = len_l;
            zmcrypto_memcpy(ctx->length.data, len_d, len_l);

            ctx->value.data = zmcrypto_malloc(val_l);
            ctx->value.dlen = val_l;
            zmcrypto_memcpy(ctx->value.data, val_d, val_l);

            if (next_d)
            {
                ctx->next.data = zmcrypto_malloc(next_l);
                ctx->next.dlen = next_l;
                zmcrypto_memcpy(ctx->next.data, next_d, next_l);
            }
        }
        else
        {
            ctx->tag.data = tag_d;
            ctx->tag.dlen = tag_l;

            ctx->length.data = len_d;
            ctx->length.dlen = len_l;

            ctx->value.data = val_d;
            ctx->value.dlen = val_l;

            if (next_d)
            {
                ctx->next.data = next_d;
                ctx->next.dlen = next_l;
                //ZMCRYPTO_LOG("");
            }
        }

        //ZMCRYPTO_LOG("successed");
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    uint8_t* asn1_get_tag_data(struct asn1_ctx* ctx)
    {
        return ctx->tag.data;
    }

    uint8_t* asn1_get_length_data(struct asn1_ctx* ctx)
    {
        return ctx->length.data;
    }

    uint8_t* asn1_get_value_data(struct asn1_ctx* ctx)
    {
        return ctx->value.data;
    }

    uint8_t* asn1_get_next_data(struct asn1_ctx* ctx)
    {
        return ctx->next.data;
    }

    uint32_t asn1_get_tag_dlen(struct asn1_ctx* ctx)
    {
        return ctx->tag.dlen;
    }

    uint32_t asn1_get_length_dlen(struct asn1_ctx* ctx)
    {
        return ctx->length.dlen;
    }

    uint32_t asn1_get_value_dlen(struct asn1_ctx* ctx)
    {
        return ctx->value.dlen;
    }

    uint32_t asn1_get_next_dlen(struct asn1_ctx* ctx)
    {
        return ctx->next.dlen;
    }

    zmerror asn1_is_tag_boolean(uint8_t tag)
    {
        return (ASN1_TAG_BOOLEAN == tag ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }
    
    zmerror asn1_is_tag_integer(uint8_t tag)
    {
        return (ASN1_TAG_INTEGER == tag ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }

    zmerror asn1_is_tag_bit_string(uint8_t tag)
    {
        return ((ASN1_TAG_BIT_STRING == (ASN1_MASK_VAL & tag)) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }

    zmerror asn1_is_tag_octet_string(uint8_t tag)
    {
        return ((ASN1_TAG_OCTET_STRING == (ASN1_MASK_VAL & tag)) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }

    zmerror asn1_is_tag_null(uint8_t tag)
    {
        return (ASN1_TAG_NULL == tag ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }
    
    zmerror asn1_is_tag_object_identifier(uint8_t tag)
    {
        return (ASN1_TAG_OBJECT_IDENTIFIER == tag ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }

    zmerror asn1_is_tag_external(uint8_t tag)
    {
        return (((ASN1_MASK_PC & tag) >> 5) == ASN1_PC_CONSTRUCTED && (ASN1_MASK_VAL & tag) == ASN1_TAG_EXTERNAL) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_real(uint8_t tag)
    {
        return (ASN1_TAG_REAL == tag ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }

    zmerror asn1_is_tag_object_descriptor(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_OBJECT_DESCRIPTOR) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_enumerated(uint8_t tag)
    {
        return (ASN1_TAG_ENUMERATED == tag ? ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG);
    }

    zmerror asn1_is_tag_embedded_pdv(uint8_t tag)
    {
         return (((ASN1_MASK_PC & tag) >> 5) == ASN1_PC_CONSTRUCTED && (ASN1_MASK_VAL & tag) == ASN1_TAG_EMBEDDED_PDV) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;   
    }
    
    zmerror asn1_is_tag_utf8_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_UTF8_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_sequence(uint8_t tag)
    {
        return (((ASN1_MASK_PC & tag) >> 5) == ASN1_PC_CONSTRUCTED && (ASN1_MASK_VAL & tag) == ASN1_TAG_SEQUENCE) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_set(uint8_t tag)
    {
        return (((ASN1_MASK_PC & tag) >> 5) == ASN1_PC_CONSTRUCTED && (ASN1_MASK_VAL & tag) == ASN1_TAG_SET) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_numeric_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_NUMERIC_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_printable_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_PRINTABLE_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_t61_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_T61_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_ia5_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_IA5_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_utc_time(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_UTC_TIME) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_generalized_time(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_GENERALIZED_TIME) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_graphic_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_GRAPHIC_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_visible_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_VISIBLE_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_general_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_GENERAL_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }

    zmerror asn1_is_tag_universal_string(uint8_t tag)
    {
        return ((ASN1_MASK_VAL & tag) == ASN1_TAG_UNIVERSAL_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;
    }
    
    zmerror asn1_is_tag_bmp_string(uint8_t tag)
    {
         return (((ASN1_MASK_PC & tag) >> 5) == ASN1_PC_CONSTRUCTED && (ASN1_MASK_VAL & tag) == ASN1_TAG_BMP_STRING) ? 
            ZMCRYPTO_ERR_SUCCESSED : ZMCRYPTO_ERR_ASN1_INVALID_TAG;   
    }

    const char* asn1_debug_tag_to_string(uint8_t tag)
    {
        uint8_t _class = (tag & ASN1_MASK_CLASS) >> 6;
        uint8_t _pc = (tag & ASN1_MASK_PC) >> 5;
        uint8_t _tag_num = (tag & ASN1_MASK_VAL);

        for (int i = 0; i < sizeof(zm_tag_map) / sizeof(zm_tag_map[0]); i++){
            if (zm_tag_map[i].val == _tag_num) { return zm_tag_map[i].str; }
        }

        static tag_info[50];
        zmcrypto_memset(tag_info, 0, 50);

        static const char *const class_text[] =
            { "UNIVERSAL", "APPLICATION", "CONTEXT", "PRIVATE" };

        static const char *const pc_text[] =
            { "PRIMITIVE", "CONSTRUCTED" };

        zmcrypto_sprintf(tag_info, "%s[0x%02x]", class_text[_class], _tag_num);
        /* zmcrypto_printf("%s\n", tag_info); */

        return tag_info;
    }

    /* get length of length data */
    zmerror asn1_parse_data_length (uint8_t* data, uint32_t dlen, uint32_t* result)
    {
        uint8_t* start = data;
        uint8_t* end = data + dlen;

        if (dlen >= 1 && ((*start & 0x80) == 0))
        {
            *result = (uint32_t)(*start);
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        uint32_t len_byte = ((*start) & ASN1_MASK_LEN);
        start++; /* skip one byte */

        switch (len_byte)
        {
            case 1:
                if (end - start < 0) 
                    { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
                *result = (uint32_t)(*start);
                break;
            case 2:
                if (end - (start + 1) < 0) 
                    { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
                *result  = ((uint32_t)(*(start + 0)) << 8) | 
                    (uint32_t)(*(start + 1)); 
                break;
            case 3:
                if (end - (start + 2) < 0) 
                    { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
                *result = ((uint32_t)(*(start + 0)) << 16) | 
                    ((uint32_t)(*(start + 1)) << 8) | 
                    (uint32_t)(*(start + 2)); 
                break;
            case 4:
                if (end - (start + 3) < 0) 
                    { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
                *result = ((uint32_t)(*(start + 0)) << 24) | 
                    ((uint32_t)(*(start + 1)) << 16) | 
                    ((uint32_t)(*(start + 2)) << 8) | 
                    (uint32_t)(*(start + 3)); 
                break;
            default:
                return ZMCRYPTO_ERR_ASN1_INVALID_VAL;
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /* result is 0 for False, otherwise result is 1 */
    zmerror asn1_parse_data_boolean(uint8_t* data, uint32_t dlen, zmbool* result)
    {
        if (dlen != 1) { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

        /*
        BER: the octet shall have any non-zero value, as a sender's option.
        DER: True is 0x00, False is 0xff;
        */
        if (data[0] == 0x00) { *result = zmfalse; return ZMCRYPTO_ERR_SUCCESSED; }
        if (data[0] == 0xff) { *result = zmtrue; return ZMCRYPTO_ERR_SUCCESSED; }

        return ZMCRYPTO_ERR_ASN1_INVALID_VAL;
    }

    zmerror asn1_is_tag_constructed(uint8_t tag, zmbool* result)
    {
        *result = (((tag & ASN1_MASK_PC) >> 5) == ASN1_PC_CONSTRUCTED) ? zmtrue : zmfalse;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_TOOL_ASN1 */
