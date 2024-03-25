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

        zmerror err;
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
            return ZMCRYPTO_ERR_OVERFLOW;
        }

        len_d = start;
        len_l = (uint32_t)(end - start + 1);
        if (asn1_decode_length(len_d, &len_l, &len_len) != ZMCRYPTO_ERR_SUCCESSED)
            { return err; }
        else
            { start += len_l; }

        val_d = start;
        val_l = len_len;
        start += len_len; /* skip value data */

        if ((start - 1) > end)
        {
            //ZMCRYPTO_LOG("start: %p(%02x), end: %p(%02x), dlen: %08x(%d)", start, *start, end, *end, dlen, dlen);
            return ZMCRYPTO_ERR_OVERFLOW;
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

        static char tag_info[50];
        zmcrypto_memset(tag_info, 0, 50);

        static const char *const class_text[] =
            { "UNIVERSAL", "APPLICATION", "CONTEXT", "PRIVATE" };

        static const char *const pc_text[] =
            { "PRIMITIVE", "CONSTRUCTED" };

        zmcrypto_sprintf(tag_info, "%s[0x%02x]", class_text[_class], _tag_num);
        /* zmcrypto_printf("%s\n", tag_info); */

        return tag_info;
    }

    zmerror asn1_is_tag_constructed(uint8_t tag, zmbool* result)
    {
        *result = (((tag & ASN1_MASK_PC) >> 5) == ASN1_PC_CONSTRUCTED) ? zmtrue : zmfalse;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror asn1_encode_boolean(zmbool in, uint8_t* out, uint32_t* olen)
    {
        if (*olen < 3) 
            { return ZMCRYPTO_ERR_OVERFLOW; }

        out[0] = ASN1_TAG_BOOLEAN;
        out[1] = 0x01;

        /*
        BER: the octet shall have any non-zero value, as a sender's option.
        DER: True is 0x00, False is 0xff;
        */
        out[2] = (in == zmtrue ? 0x00 : 0xff);
        *olen = 3;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror asn1_decode_boolean(uint8_t* in, uint32_t ilen, zmbool* out)
    {
        if (ilen != 3) 
            { return ZMCRYPTO_ERR_OVERFLOW; }

        if (in[0] != ASN1_TAG_BOOLEAN)
            { return ZMCRYPTO_ERR_ASN1_INVALID_TAG; }

        if (in[1] != 0x01)
            { return ZMCRYPTO_ERR_ASN1_INVALID_LEN; }

        if (in[2] != 0x00 && in[2] != 0xff)
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

        *out = (in[2] == 0x00 ? zmtrue :zmfalse);
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror asn1_encode_length(uint32_t in, uint8_t* out, uint32_t* olen)
    {
        uint32_t i = 0;
        uint32_t count_bytes = 0;
        UINT32_BYTE_COUNT(in, count_bytes);

        if (count_bytes == 0)
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

        if (in > 128)
            { count_bytes++; }

        if (!out)
        {
            *olen = count_bytes;
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        if (*olen < count_bytes)
            { return ZMCRYPTO_ERR_OVERFLOW; }

        if (in < 128)
        {
            out[i++] = (uint8_t)in;
        }
        else if (in <= 0xffU)
        {
            out[i++] = 0x81;
            out[i++] = (uint8_t)in;
        }
        else if (in <= 0xffffU)
        {
            out[i++] = 0x82;
            out[i++] = (uint8_t)(in >> 8 & 0xff);
            out[i++] = (uint8_t)(in      & 0xff);
        }
        else if (in <= 0xffffffU)
        {
            out[i++] = 0x83;
            out[i++] = (uint8_t)(in >> 16 & 0xff);
            out[i++] = (uint8_t)(in >>  8 & 0xff);
            out[i++] = (uint8_t)(in       & 0xff);
        }
        /* else: No need to handle, because we are using 32-bit numbers */

        *olen = i;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror asn1_decode_length(uint8_t* in, uint32_t* ilen, uint32_t* out)
    {
        if (*ilen < 1)
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
        
        if (in[0] < 128)
        {
            *out = (uint32_t)(in[0]);
            *ilen = 1;
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        uint32_t len_byte = in[0] & 0x7f;
        if (len_byte == 0 || (len_byte + 1) > *ilen ||
            len_byte > 4/*more then 4GB, don't implement it for now */)
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

        uint32_t len = 0;
        for (uint32_t i = 0; i < len_byte; i++)
            { len = len << 8 | in[i + 1]; }

        if (len < 128)
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
            
        *out = len;
        *ilen = len_byte + 1;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /*
    // Implementation principle
    //   The decimal number 113549 will be encoded as hexadecimal 86 f7 0d, 
    //   The encoding process is as follows
    //   113549 => 0x01 bb 8d => 
    //   00000001   10111011   10001101 => raw binary
    //    0000110    1110111    0001101 => Split into one segment every 7 bits
    // [1]0000110 [1]1110111 [0]0001101 => The highest bit at the beginning of each segment is 1, and the highest bit in the last segment is 0.
    //   |          |          |
    //   V          V          V
    //   86         f7         0d
    // --------------------------------------
    // 840 => 0x03 48 => 
    // 00000011 01001000 =>
    //  0000110  1001000 =>
    // 10000110 01001000 =>
    // |        |
    // V        V
    // 86       48
    */
    /*
    // example
    // 06 08 2a 86 48 86 f7 0d 02 02    => 1.2.840.113549.2.2    
    // 06 08 2a 86 48 86 f7 0d 02 04    => 1.2.840.113549.2.4    
    // 06 08 2a 86 48 86 f7 0d 02 05    => 1.2.840.113549.2.5    
    // 06 05 2b 0e 03 02 1a             => 1.3.14.3.2.26         
    // 06 09 60 86 48 01 65 03 04 02 01 => 2.16.840.1.101.3.4.2.1
    // 06 09 60 86 48 01 65 03 04 02 02 => 2.16.840.1.101.3.4.2.2
    // 06 09 60 86 48 01 65 03 04 02 03 => 2.16.840.1.101.3.4.2.3
    */
    zmerror asn1_encode_object_identifier(uint32_t* in, uint32_t ilen, uint8_t* out, uint32_t* olen)
    {
        if (ilen < 2) 
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

        /* word1 = 0,1,2 and word2 0..39 */
        if (in[0] > 2 || (in[0] < 2 && in[1] > 39)) 
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }
        
        /**
         * 
         * First calculate how much memory is needed (T | L | V)
         * 
         */

        /*leading word is the first two*/
        uint32_t x = 0;
        uint32_t y = 0;
        uint32_t z = 0;
        uint32_t t = 0;
        uint32_t mask = 0;
        uint32_t word_buffer = 0;
        uint32_t len_len = 0;

        word_buffer = in[0] * 40 + in[1];
        x++;

        for (uint32_t i = 2; i < ilen; i++)
        {
            word_buffer = in[i];
            UINT32_BIT_COUNT(word_buffer, t);
            x += (t / 7) + (t % 7 ? 1 : 0) + (word_buffer == 0 ? 1 : 0);
        }

        len_len = x;

        /* now depending on the length our length encoding changes */
        if (x < 128)
            { x += 2;  }
        else if (x < 256)
            { x += 3;  }
        else if (x < 65536UL)
            { x += 4;  }
        else
            { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

        if (!out)
        {
            *olen = x; 
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        if (*olen < x)
            { return ZMCRYPTO_ERR_OVERFLOW; }

        /**
         * 
         * Encode tag
         * 
         */

        x = 0;
        out[x++] = ASN1_TAG_OBJECT_IDENTIFIER;

        /**
         * 
         * Encode length
         * 
         */
        zmerror err = asn1_encode_length(len_len, (uint8_t*) (&out[x]), (uint32_t*) (&len_len));
        if (ZMCRYPTO_IS_ERROR(err))
            { return err; }
        x += len_len;

        /**
         * 
         * Encode value
         * 
         */

        word_buffer = in[0] * 40 + in[1];
        out[x++] = (uint8_t)word_buffer;

        for (uint32_t i = 2; i < ilen; i++)
        {
            word_buffer = in[i];
            t = word_buffer & 0xffffffff;

            if (t > 0)
            {
                y = x;
                mask = 0;

                while (t)
                {
                    out[x++] = (uint8_t)(t & 0x7f | mask);
                    t >>= 7;
                    mask = 0x80; /*upper bit is set on all but the last byte*/
                }
                /*
                When calculating, the high byte is processed first, and when storing, 
                the low byte needs to be stored first.
                now swap bytes y...x-1
                */
                z = x - 1;
                while (y < z)
                {
                    t = out[y]; out[y] = out[z]; out[z] = (uint8_t)t;
                    ++y;
                    --z;
                }
            }
            else
            {
                out[x++] = 0x00;/* zero word */
            }
        }

        *olen = x; 
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /*Only decode the data part*/
    zmerror asn1_decode_object_identifier(uint8_t* in, uint32_t ilen, uint32_t* out, uint32_t* olen)
    {
        if (*olen < 2)
            { return ZMCRYPTO_ERR_OVERFLOW; }

        uint32_t t = 0;
        uint32_t x = 0;
        uint32_t y = 0;

        t = in[0];
        out[y++] = t / 40;
        out[y++] = t % 40;

        t = 0;
        x = 0;
        for (uint32_t i = 1; i < ilen; i++)
        {
            t = t << 7 | (in[i] & 0x7f);
            x++;
            if (in[i] >> 7 == 0)
            {
                if (x > 4)
                    { return ZMCRYPTO_ERR_ASN1_INVALID_VAL; }

                if (*olen < (y + 1))
                    { return ZMCRYPTO_ERR_OVERFLOW; }

                out[y++] = t;
                t = 0;
                x = 0;
            }
        }

        *olen = y;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_TOOL_ASN1 */
