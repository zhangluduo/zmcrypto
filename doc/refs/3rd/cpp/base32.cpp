/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "base32.h"

#if (_MSC_VER < 1800)  && defined _MSC_VER
	#include <wchar.h>
    #include "msinttypes/inttypes.h"
    #include "msinttypes/stdint.h"
#else
    #include <stdint.h>
    #include <inttypes.h>
#endif

//#ifdef LTC_BASE32

/**
   Base32 encode a buffer
   @param in       The input buffer to encode
   @param inlen    The length of the input buffer
   @param out      [out] The destination of the Base32 encoded data
   @param outlen   [in/out] The max size and resulting size of the encoded data
   @param id       Alphabet to use BASE32_RFC4648, BASE32_BASE32HEX, BASE32_ZBASE32 or BASE32_CROCKFORD
   @return CRYPT_OK if successful
*/

int base32_encode(const unsigned char *in,  unsigned long inlen,
                  char *out, unsigned long *outlen,
                  /*base32_alphabet*/ int options)
{
    if (!in) return -1;
    else if (inlen == 0) return -2;
    else if (!out) return -3;
    else if (!outlen) return -4;
    
    unsigned long i, x;

    /* add by Zhang Luduo begin */
    int hi = options >> 16;   /* pad*/
    int lo = options & 0xFF;  /* table index */

    /* check the size of output buffer +1 byte for terminating NUL */
    if (hi == 1) /*pad*/
        x = (inlen + 4) / 5 * 8 + 1;
    else if (hi == 0)/*no pad*/
        x = (8 * inlen + 4) / 5 + 1;
    else
        return -5;

    if (!(lo >= 0 && lo < 4))
        return -5;

    const char *codes;
    const char *alphabet[4] = {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",     /* id = BASE32_RFC4648   */
        "0123456789ABCDEFGHIJKLMNOPQRSTUV",     /* id = BASE32_BASE32HEX */
        "ybndrfg8ejkmcpqxot1uwisza345h769",     /* id = BASE32_ZBASE32   */
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ"      /* id = BASE32_CROCKFORD */
    };

    if (*outlen < x) {
        *outlen = x;
        return -6;//CRYPT_BUFFER_OVERFLOW;
    }

    *outlen = x - 1; /* returning the length without terminating NUL */

    /* no input, nothing to do */
    if (inlen == 0) {
        *out = '\0';
        return 0;//CRYPT_OK;
    }

    codes = alphabet[lo];
    x = 5 * (inlen / 5);
    for (i = 0; i < x; i += 5) {
        *out++ = codes[(in[0] >> 3) & 0x1F];
        *out++ = codes[(((in[0] & 0x7) << 2) + (in[1] >> 6)) & 0x1F];
        *out++ = codes[(in[1] >> 1) & 0x1F];
        *out++ = codes[(((in[1] & 0x1) << 4) + (in[2] >> 4)) & 0x1F];
        *out++ = codes[(((in[2] & 0xF) << 1) + (in[3] >> 7)) & 0x1F];
        *out++ = codes[(in[3] >> 2) & 0x1F];
        *out++ = codes[(((in[3] & 0x3) << 3) + (in[4] >> 5)) & 0x1F];
        *out++ = codes[in[4] & 0x1F];
        in += 5;
    }

    if (i < inlen) {
        unsigned a = in[0];
        unsigned b = (i + 1 < inlen) ? in[1] : 0;
        unsigned c = (i + 2 < inlen) ? in[2] : 0;
        unsigned d = (i + 3 < inlen) ? in[3] : 0;
        *out++ = codes[(a >> 3) & 0x1F];
        *out++ = codes[(((a & 0x7) << 2) + (b >> 6)) & 0x1F];
        if (i + 1 < inlen) {
            *out++ = codes[(b >> 1) & 0x1F];
            *out++ = codes[(((b & 0x1) << 4) + (c >> 4)) & 0x1F];
        }
        if (i + 2 < inlen) {
            *out++ = codes[(((c & 0xF) << 1) + (d >> 7)) & 0x1F];
        }
        if (i + 3 < inlen) {
            *out++ = codes[(d >> 2) & 0x1F];
            *out++ = codes[((d & 0x3) << 3) & 0x1F];
        }
        /* RFC4648 [page 9]
        (1) The final quantum of encoding input is an integral multiple of 40
            bits; here, the final unit of encoded output will be an integral
            multiple of 8 characters with no "=" padding.

        (2) The final quantum of encoding input is exactly 8 bits; here, the
            final unit of encoded output will be two characters followed by
            six "=" padding characters.

        (3) The final quantum of encoding input is exactly 16 bits; here, the
            final unit of encoded output will be four characters followed by
            four "=" padding characters.

        (4) The final quantum of encoding input is exactly 24 bits; here, the
            final unit of encoded output will be five characters followed by
            three "=" padding characters.

        (5) The final quantum of encoding input is exactly 32 bits; here, the
            final unit of encoded output will be seven characters followed by
            one "=" padding character.
        */

        if (hi) /*pad*/
        {
            if (inlen - i == 1){
                for (i = 0; i < 6; i++)
                    *out++ = '=';
            }
            else if (inlen - i == 2){
                for (i = 0; i < 4; i++)
                    *out++ = '=';
            }
            else if (inlen - i == 3){
                for (i = 0; i < 3; i++)
                    *out++ = '=';
            }
            else if (inlen - i == 4){
                *out++ = '=';
            }
        }
    }
    *out = '\0';
    return 0;//CRYPT_OK;
}

/**
   Base32 decode a buffer
   @param in       The Base32 data to decode
   @param inlen    The length of the Base32 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @param id       Alphabet to use BASE32_RFC4648, BASE32_BASE32HEX, BASE32_ZBASE32 or BASE32_CROCKFORD
   @return CRYPT_OK if successful
*/

int base32_decode(const char *in,  unsigned long inlen,
                  unsigned char *out, unsigned long *outlen,
                  int options)
{
    if (!in) return -1;
    else if (inlen == 0) return -2;
    else if (!out) return -3;
    else if (!outlen) return -4;

    /* add by Zhang Luduo begin */
    uint16_t hi = options >> 16;  /* skip whitespace */
    uint16_t lo = options & 0xFF; /* table index */
    if (!(lo >= 0 && lo <= 4)){
        return -5;//invalid param
    }
    /* add by Zhang Luduo end */

   unsigned long x;
   int y = 0;
   uint64_t t = 0;
   char c;
   const unsigned char *map;
   const unsigned char tables[4][43] = {
      {  /* id = BASE32_RFC4648 : ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 */
         99/*0*/,99/*1*/,26/*2*/,27/*3*/,28/*4*/,29/*5*/,30/*6*/,31/*7*/,99/*8*/,99/*9*/,
         99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
          0/*A*/, 1/*B*/, 2/*C*/, 3/*D*/, 4/*E*/, 5/*F*/, 6/*G*/, 7/*H*/, 8/*I*/, 9/*J*/,10/*K*/,11/*L*/,12/*M*/,
         13/*N*/,14/*O*/,15/*P*/,16/*Q*/,17/*R*/,18/*S*/,19/*T*/,20/*U*/,21/*V*/,22/*W*/,23/*X*/,24/*Y*/,25/*Z*/
      },
      {  /* id = BASE32_BASE32HEX : 0123456789ABCDEFGHIJKLMNOPQRSTUV */
           0/*0*/, 1/*1*/, 2/*2*/, 3/*3*/, 4/*4*/, 5/*5*/, 6/*6*/, 7/*7*/, 8/*8*/, 9/*9*/,
          99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
          10/*A*/,11/*B*/,12/*C*/,13/*D*/,14/*E*/,15/*F*/,16/*G*/,17/*H*/,18/*I*/,19/*J*/,20/*K*/,21/*L*/,22/*M*/,
          23/*N*/,24/*O*/,25/*P*/,26/*Q*/,27/*R*/,28/*S*/,29/*T*/,30/*U*/,31/*V*/,99/*W*/,99/*X*/,99/*Y*/,99/*Z*/
      },
      {  /* id = BASE32_ZBASE32 : YBNDRFG8EJKMCPQXOT1UWISZA345H769 */
         99/*0*/,18/*1*/,99/*2*/,25/*3*/,26/*4*/,27/*5*/,30/*6*/,29/*7*/, 7/*8*/,31/*9*/,
         99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
         24/*A*/, 1/*B*/,12/*C*/, 3/*D*/, 8/*E*/, 5/*F*/, 6/*G*/,28/*H*/,21/*I*/, 9/*J*/,10/*K*/,99/*L*/,11/*M*/,
          2/*N*/,16/*O*/,13/*P*/,14/*Q*/, 4/*R*/,22/*S*/,17/*T*/,19/*U*/,99/*V*/,20/*W*/,15/*X*/, 0/*Y*/,23/*Z*/
      },
      {  /* id = BASE32_CROCKFORD : 0123456789ABCDEFGHJKMNPQRSTVWXYZ + O=>0 + IL=>1 */
          0/*0*/, 1/*1*/, 2/*2*/, 3/*3*/, 4/*4*/, 5/*5*/, 6/*6*/, 7/*7*/, 8/*8*/, 9/*9*/,
         99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
         10/*A*/,11/*B*/,12/*C*/,13/*D*/,14/*E*/,15/*F*/,16/*G*/,17/*H*/, 1/*I*/,18/*J*/,19/*K*/, 1/*L*/,20/*M*/,
         21/*N*/, 0/*O*/,22/*P*/,23/*Q*/,24/*R*/,25/*S*/,26/*T*/,99/*U*/,27/*V*/,28/*W*/,29/*X*/,30/*Y*/,31/*Z*/
      }
   };

   /* ignore all trailing = */
   while (inlen > 0 && in[inlen-1] == '=') inlen--;

   /* no input, nothing to do */
   if (inlen == 0) {
      *outlen = 0;
      return 0;//CRYPT_OK;
   }

   /* check the size of output buffer */
   x = (inlen * 5) / 8;
   if (*outlen < x) {
      *outlen = x;
      return -6;//CRYPT_BUFFER_OVERFLOW;
   }

   /**outlen = x; */

   /* check input data length */
   /*
   x = inlen % 8;
   if (x == 1 || x == 3 || x == 6) {
      return -1;//CRYPT_INVALID_PACKET;
   }*/

   int count = 0;
   map = tables[lo];
   for (x = 0; x < inlen; x++) {
      c = in[x];
      /* convert to upper case */
      if ((c >= 'a') && (c <= 'z')) c -= 32;
      if (c < '0' || c > 'Z' || map[c-'0'] > 31) {
         if (hi == 1)
            continue;
         return -7;//CRYPT_INVALID_PACKET;
      }
      t = (t<<5) | map[c-'0'];
      if (++y == 8) {
         *out++ = (unsigned char)((t>>32) & 255);
         *out++ = (unsigned char)((t>>24) & 255);
         *out++ = (unsigned char)((t>>16) & 255);
         *out++ = (unsigned char)((t>> 8) & 255);
         *out++ = (unsigned char)( t      & 255);
         y = 0;
         t = 0;
         count += 5;
      }
   }

   if (y > 0) {
        if (y == 1 || y == 3 || y == 6) {
            return -7;//CRYPT_INVALID_PACKET;
        }
      t = t << (5 * (8 - y));
      if (y >= 2) {*out++ = (unsigned char)((t>>32) & 255); count ++;}
      if (y >= 4) {*out++ = (unsigned char)((t>>24) & 255); count ++;}
      if (y >= 5) {*out++ = (unsigned char)((t>>16) & 255); count ++;}
      if (y >= 7) {*out++ = (unsigned char)((t>> 8) & 255); count ++;}
   }

   *outlen = count;
   return 0;//CRYPT_OK;
}

//#endif
