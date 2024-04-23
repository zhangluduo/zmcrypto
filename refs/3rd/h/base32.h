/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#if !defined _BASE32_HEADER_H
#define _BASE32_HEADER_H

/**
   Base32 encode a buffer
   @param in       The input buffer to encode
   @param inlen    The length of the input buffer
   @param out      [out] The destination of the Base32 encoded data
   @param outlen   [in/out] The max size and resulting size of the encoded data
   @param options  hight 16 bits: 1 pad, or 0 no pad, lower 16 bits: mapping code table index (>0 && <4)
   @return CRYPT_OK if successful
*/
int base32_encode(const unsigned char *in,  unsigned long inlen,
                  char *out, unsigned long *outlen,
                  /*base32_alphabet*/ int options);

/**
   Base32 decode a buffer
   @param in       The Base32 data to decode
   @param inlen    The length of the Base32 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @param options  hight 16 bits: Allow skip '\r', '\n', '\t' and space characters 
                   on 1 or not allowed otherwise, lower 16 bits: alphabet to use 
                   BASE32_RFC4648, BASE32_BASE32HEX, BASE32_ZBASE32 or BASE32_CROCKFORD
   @return CRYPT_OK if successful
*/
int base32_decode(const char *in,  unsigned long inlen,
                  unsigned char *out, unsigned long *outlen,
                  int options);

#endif
