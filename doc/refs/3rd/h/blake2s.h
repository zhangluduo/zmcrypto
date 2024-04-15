// blake2s.h
// BLAKE2s Hashing Context and API Prototypes

#ifndef BLAKE2S_H
#define BLAKE2S_H

#if (_MSC_VER < 1800) && defined _MSC_VER
	#include <wchar.h>
    #include "msinttypes/inttypes.h"
    #include "msinttypes/stdint.h"
#else
    #include <stdint.h>
    #include <inttypes.h>
#endif

namespace blake2s
{
#define _BLAKE2S_BLOCK 64
#if !defined NULL
#define NULL 0
#endif

// state context
typedef struct {
   uint8_t b[64];                      // input buffer
   uint32_t h[8];                      // chained state
   uint32_t t[2];                      // total number of bytes
   int c;                           // pointer for b[]
   int outlen;                      // digest size
   unsigned char ipad[_BLAKE2S_BLOCK];
   unsigned char opad[_BLAKE2S_BLOCK];
} blake2s_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 32 gives the digest size in bytes.
//      Secret key (also <= 32 bytes) is optional (keylen = 0).
int blake2s_init(blake2s_ctx *ctx, int outlen,
   const void *key, int keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
void blake2s_update(blake2s_ctx *ctx,   // context
   const void *in, int inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2s_final(blake2s_ctx *ctx, void *out);

// All-in-one convenience function.
int blake2s(void *out, int outlen,   // return buffer for digest
   const void *key, int keylen,     // optional secret key
   const void *in, int inlen);      // data to be hashed

// Add by Zhang Luduo, 2020-06-10
int blake2s_hmac_starts( blake2s_ctx *ctx, int outlen, const void *key, int keylen);
void blake2s_hmac_update( blake2s_ctx *ctx, const void *in, int inlen);
void blake2s_hmac_finish( blake2s_ctx *ctx, void *out);
}//namespace blake2s
#endif