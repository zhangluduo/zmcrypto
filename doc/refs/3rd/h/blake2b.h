// blake2b.h
// BLAKE2b Hashing Context and API Prototypes

#ifndef BLAKE2B_H
#define BLAKE2B_H

#if (_MSC_VER < 1800) && defined _MSC_VER
	#include <wchar.h>
    #include "msinttypes/inttypes.h"
    #include "msinttypes/stdint.h"
#else
    #include <stdint.h>
    #include <inttypes.h>
#endif

namespace blake2b
{
#define _BLAKE2B_BLOCK 128
#if !defined NULL
#define NULL 0
#endif
// state context
typedef struct {
   uint8_t b[128];                     // input buffer
   uint64_t h[8];                      // chained state
   uint64_t t[2];                      // total number of bytes
   uint64_t c;                           // pointer for b[]
   uint64_t outlen;                      // digest size
   unsigned char ipad[_BLAKE2B_BLOCK];
   unsigned char opad[_BLAKE2B_BLOCK];
} blake2b_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
int blake2b_init(blake2b_ctx *ctx, int outlen,
   const void *key, int keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
void blake2b_update(blake2b_ctx *ctx,   // context
   const void *in, int inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2b_final(blake2b_ctx *ctx, void *out);

// All-in-one convenience function.
int blake2b(void *out, int outlen,   // return buffer for digest
   const void *key, int keylen,     // optional secret key
   const void *in, int inlen);      // data to be hashed

// Add by Zhang Luduo, 2020-06-10
int blake2b_hmac_starts(blake2b_ctx *ctx, int outlen, const void *key, int keylen);
void blake2b_hmac_update(blake2b_ctx *ctx, const void *in, int inlen);
void blake2b_hmac_finish(blake2b_ctx *ctx, void *out);
}//namespace blake2b
#endif
