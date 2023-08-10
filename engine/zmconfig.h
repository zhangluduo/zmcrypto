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

#if !defined ZMCRYPTO_CONFIG_H
#define ZMCRYPTO_CONFIG_H

/**
 * About the definition of integer data:
 * uint64_t, uint32_t, uint16_t, uint8_t, 
 * int64_t, int32_t, int16_t, int8_t,
 * size_t
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * About error code handling
 */

/* Less than or equal to zero fails, greater than zero succeeds */
typedef int32_t zmerror;

#define ZMCRYPTO_ERR_SUCCESSED                 (zmerror)(0x00000001L)
#define ZMCRYPTO_ERR_BASE                      (zmerror)(0x00000000L)
#define ZMCRYPTO_ERR_NULL_PTR                  (zmerror)(ZMCRYPTO_ERR_BASE - 0x0001) /* NULL pointer  */
#define ZMCRYPTO_ERR_INVALID_KSIZE             (zmerror)(ZMCRYPTO_ERR_BASE - 0x0002) /* invalid key size */
#define ZMCRYPTO_ERR_INVALID_DSIZE             (zmerror)(ZMCRYPTO_ERR_BASE - 0x0003) /* invalid data size */
#define ZMCRYPTO_ERR_INVALID_BSIZE             (zmerror)(ZMCRYPTO_ERR_BASE - 0x0004) /* invalid block size */
#define ZMCRYPTO_ERR_INVALID_TSIZE             (zmerror)(ZMCRYPTO_ERR_BASE - 0x0005) /* invalid tag/MAC size */
#define ZMCRYPTO_ERR_INVALID_IVSIZE            (zmerror)(ZMCRYPTO_ERR_BASE - 0x0006) /* invalid IV/N-once size */
#define ZMCRYPTO_ERR_INVALID_PAD               (zmerror)(ZMCRYPTO_ERR_BASE - 0x0007) /* invalid padding */
#define ZMCRYPTO_ERR_INVALID_DATA              (zmerror)(ZMCRYPTO_ERR_BASE - 0x0009) /* invalid input data */
#define ZMCRYPTO_ERR_WEAK_KEY                  (zmerror)(ZMCRYPTO_ERR_BASE - 0x000a) /* Weak keys for DES, RC4, IDEA, Blowfish etc. */
#define ZMCRYPTO_ERR_MALLOC_FAILED             (zmerror)(ZMCRYPTO_ERR_BASE - 0x000b) /* malloc memory failed */
#define ZMCRYPTO_ERR_OVERFLOW                  (zmerror)(ZMCRYPTO_ERR_BASE - 0x000c) /* buffer to small */
#define ZMCRYPTO_ERR_CALLBACK                  (zmerror)(ZMCRYPTO_ERR_BASE - 0x000d) /* The callback function returns failed */

#define ZMCRYPTO_IS_ERROR(code) (code <= ZMCRYPTO_ERR_BASE)
#define ZMCRYPTO_IS_SUCCESSED(code) (code > ZMCRYPTO_ERR_BASE)

#define MAX_BLOCKSIZE 16
#define MAX_DIGESTSIZE 64

/*
Use the following macros to make this library do clipping
*/

/* Non-Cryptographic Checksums */
    #define ZMCRYPTO_ALGO_ADLER32
    #define ZMCRYPTO_ALGO_CRC32

/* Keyless Hash */
    #define ZMCRYPTO_ALGO_MD2
    #define ZMCRYPTO_ALGO_MD4
    #define ZMCRYPTO_ALGO_MD5
    #define ZMCRYPTO_ALGO_MD6
    #define ZMCRYPTO_ALGO_ED2K
    #define ZMCRYPTO_ALGO_SHA1
    #define ZMCRYPTO_ALGO_SHA256
    #define ZMCRYPTO_ALGO_SHA512
    #define ZMCRYPTO_ALGO_SHA3
    #define ZMCRYPTO_ALGO_RIPEMD128
    #define ZMCRYPTO_ALGO_RIPEMD160
    #define ZMCRYPTO_ALGO_RIPEMD256
    #define ZMCRYPTO_ALGO_RIPEMD320
    #define ZMCRYPTO_ALGO_SM3
    #define ZMCRYPTO_ALGO_TIGER
    #define ZMCRYPTO_ALGO_WHIRLPOOL

/* With Key Hash */
    #define ZMCRYPTO_ALGO_BLAKE2B160
    #define ZMCRYPTO_ALGO_BLAKE2B256
    #define ZMCRYPTO_ALGO_BLAKE2B384
    #define ZMCRYPTO_ALGO_BLAKE2B512
    #define ZMCRYPTO_ALGO_BLAKE2S128
    #define ZMCRYPTO_ALGO_BLAKE2S160
    #define ZMCRYPTO_ALGO_BLAKE2S224
    #define ZMCRYPTO_ALGO_BLAKE2S256

/* Block Cipher */
    #define ZMCRYPTO_ALGO_3DES
    #define ZMCRYPTO_ALGO_3WAY
    #define ZMCRYPTO_ALGO_AES
    #define ZMCRYPTO_ALGO_DES
    #define ZMCRYPTO_ALGO_BLOWFISH
    #define ZMCRYPTO_ALGO_CAMELLIA
    #define ZMCRYPTO_ALGO_CAST128
    #define ZMCRYPTO_ALGO_CAST256
    #define ZMCRYPTO_ALGO_DES
    #define ZMCRYPTO_ALGO_IDEA
    #define ZMCRYPTO_ALGO_MARS
    #define ZMCRYPTO_ALGO_RC2
    #define ZMCRYPTO_ALGO_RC5
    #define ZMCRYPTO_ALGO_RC6
    #define ZMCRYPTO_ALGO_SAFER_K64
    #define ZMCRYPTO_ALGO_SAFER_K128
    #define ZMCRYPTO_ALGO_SEED
    #define ZMCRYPTO_ALGO_SERPENT
    #define ZMCRYPTO_ALGO_SM4
    #define ZMCRYPTO_ALGO_TEA
    #define ZMCRYPTO_ALGO_TWOFISH
    #define ZMCRYPTO_ALGO_XTEA

/* Stream Cipher */
    #define ZMCRYPTO_ALGO_ARC4
    #define ZMCRYPTO_ALGO_SALSA20
    #define ZMCRYPTO_ALGO_XSALSA20
    #define ZMCRYPTO_ALGO_CHACHA20

/* Binary to Text Encoders and Decoders */
    #define ZMCRYPTO_ALGO_BASE16
    #define ZMCRYPTO_ALGO_BASE32
    #define ZMCRYPTO_ALGO_BASE58
    #define ZMCRYPTO_ALGO_BASE64

/* Message Authentication Code */
    #define ZMCRYPTO_ALGO_HMAC
    #define ZMCRYPTO_ALGO_CMAC
    #define ZMCRYPTO_ALGO_POLY1305

/* Authenticated Encryption Modes */
    #define ZMCRYPTO_ALGO_ECB
    #define ZMCRYPTO_ALGO_CBC
    #define ZMCRYPTO_ALGO_CFB
    #define ZMCRYPTO_ALGO_OFB
    #define ZMCRYPTO_ALGO_CTR
    #define ZMCRYPTO_ALGO_CCM
    #define ZMCRYPTO_ALGO_GCM

/* Block Cipher Mode Of Operation */
    #define ZMCRYPTO_ALGO_ECB
    #define ZMCRYPTO_ALGO_CBC
    #define ZMCRYPTO_ALGO_CFB
    #define ZMCRYPTO_ALGO_OFB
    #define ZMCRYPTO_ALGO_CTR

/* Key Derivation and Password-based Cryptography */
    #define ZMCRYPTO_ALGO_PBKDF2

/* Public Key Cryptosystems */
    #define ZMCRYPTO_ALGO_RSAES_PKCS1_V15
    #define ZMCRYPTO_ALGO_RSAES_OAEP

/* Public Key Signature Schemes */
    #define ZMCRYPTO_ALGO_RSASSA_PKCS1_V15
    #define ZMCRYPTO_ALGO_RSASSA_PSS
    #define ZMCRYPTO_ALGO_ECDSA
    #define ZMCRYPTO_ALGO_EDDSA
    #define ZMCRYPTO_ALGO_DSA

/* Key Agreement
  #define ZMCRYPTO_ALGO_ECDH
*/

/* others */
    #define ZMCRYPTO_ALGO_BLOCKPAD

/* 
    Replace the following functions with platform-specific 
    implementations by modifying the macro definition 
*/

#if defined ZMCRYPTO_ALGO_MEM
    #include "mem.h"
    #define zmcrypto_malloc(size)                  zm_malloc(size)
    #define zmcrypto_realloc(ptr, size)            zm_realloc((ptr), (size))
    #define zmcrypto_free(ptr)                     zm_free(ptr)
    #define zmcrypto_memcpy(dst, src, size)        zm_memcpy((dst), (src), (size))
    #define zmcrypto_memcmp(s1, s2, size)          zm_memcmp((s1), (s2), (size))
    #define zmcrypto_memset(s, c, size)            zm_memset ((s), (c), (size))
#else
    #include <memory.h>
    /*default to libc stuff*/
    #define zmcrypto_malloc(size)                  malloc(size)
    #define zmcrypto_realloc(ptr, size)            realloc((ptr), (size))
    #define zmcrypto_free(ptr)                     free(ptr)
    #define zmcrypto_memcpy(dst, src, size)        memcpy((dst), (src), (size))
    #define zmcrypto_memcmp(s1, s2, size)          memcmp((s1), (s2), (size))
    #define zmcrypto_memset(s, c, size)            memset ((s), (c), (size))
#endif

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif

/* detect x86/i386 32bit */
#if defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #define ENDIAN_LITTLE
    #define ENDIAN_32BITWORD
#endif

/* detect amd64/x64 */
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
    #define ENDIAN_LITTLE
    #define ENDIAN_64BITWORD
#endif

/* detects MIPS */
#if (defined(_mips) || defined(__mips__) || defined(mips))
    #define ENDIAN_64BITWORD
    #if defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__)
        #define ENDIAN_BIG
    #else
        #define ENDIAN_LITTLE
    #endif
#endif

/* detect AIX */
#if defined(_AIX) && defined(_BIG_ENDIAN)
    #define ENDIAN_BIG
    #if defined(__LP64__) || defined(_ARCH_PPC64)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif
#endif

/* detect HP-UX */
#if defined(__hpux) || defined(__hpux__)
    #define ENDIAN_BIG
    #if defined(__ia64) || defined(__ia64__) || defined(__LP64__)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif
#endif

/* detect Apple OS X */
#if defined(__APPLE__) && defined(__MACH__)
    #if defined(__LITTLE_ENDIAN__) || defined(__x86_64__)
        #define ENDIAN_LITTLE
    #else
        #define ENDIAN_BIG
    #endif
    #if defined(__LP64__) || defined(__x86_64__)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif
#endif

/* detect SPARC and SPARC64 */
#if defined(__sparc__) || defined(__sparc)
    #define ENDIAN_BIG
    #if defined(__arch64__) || defined(__sparcv9) || defined(__sparc_v9__)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif
#endif

/* detect IBM S390(x) */
#if defined(__s390x__) || defined(__s390__)
    #define ENDIAN_BIG
    #if defined(__s390x__)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif
#endif

/* detect ARM64/AARCH64 */
#if defined(__aarch64__)
    #define ENDIAN_LITTLE
    #define ENDIAN_64BITWORD
#endif

/* endianness fallback */
#if !defined(ENDIAN_BIG) && !defined(ENDIAN_LITTLE)
    #if defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN || \
            defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
            defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ || \
            defined(__BIG_ENDIAN__) || \
            defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
            defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__)
        #define ENDIAN_BIG
    #elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN || \
            defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
            defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
            defined(__LITTLE_ENDIAN__) || \
            defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || \
            defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
       #define ENDIAN_LITTLE
    #else
        #error Cannot detect endianness
    #endif
#endif

#endif /* ZMCRYPTO_CONFIG_H */
