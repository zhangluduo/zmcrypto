/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SALSA20_H__
#define BOTAN_SALSA20_H__

typedef unsigned char    uint8_t,  byte;
typedef unsigned short   uint16_t, u16bit;

#if defined(__x86_64__) || (defined(__sparc__) && defined(__arch64__))
   typedef unsigned ulong32,uint32_t,u32bit;
#else
   typedef unsigned long ulong32, u32bit;
#endif

#ifdef _MSC_VER
   #define CONST64(n) n ## ui64
   typedef unsigned __int64 ulong64;
#else
   #define CONST64(n) n ## ULL
   typedef unsigned long long ulong64;
#endif

#include <algorithm>
#include <vector>

namespace salsa20
{
typedef struct 
{
	std::vector<u32bit> m_state;
	std::vector<byte> m_buffer;
	size_t m_position;
} salsa20_context;

void key_schedule(salsa20_context* ctx, const byte key[], size_t length);
void set_iv(salsa20_context* ctx, const byte iv[], size_t iv_len);
void salsa20(salsa20_context* ctx, byte output[64], const u32bit input[16]);
void cipher(salsa20_context* ctx, const byte in[], byte out[], size_t length);

} // namespace salsa20
#endif
