
#include "3way.h"
#include <string.h>

/********************************************************************\
*                                                                    *
* C specification of the threeway block cipher                       *
*                                                                    *
\********************************************************************/

#define   STRT_E   0x0b0b /* round constant of first encryption round */ 
#define   STRT_D   0xb1b1 /* round constant of first decryption round */
#define     NMBR       11 /* number of rounds is 11                   */

/* the program only works correctly if int = 32bits */

void mu(word32 *a)       /* inverts the order of the bits of a */
{
int i ;
word32 b[3] ;

b[0] = b[1] = b[2] = 0 ;
for( i=0 ; i<32 ; i++ )
   {
   b[0] <<= 1 ; b[1] <<= 1 ; b[2] <<= 1 ;
   if(a[0]&1) b[2] |= 1 ;
   if(a[1]&1) b[1] |= 1 ;
   if(a[2]&1) b[0] |= 1 ;
   a[0] >>= 1 ; a[1] >>= 1 ; a[2] >>= 1 ;
   }

a[0] = b[0] ; a[1] = b[1] ; a[2] = b[2] ;
}

void gamma(word32 *a)   /* the nonlinear step */
{
word32 b[3] ;

b[0] = a[0] ^ (a[1]|(~a[2])) ; 
b[1] = a[1] ^ (a[2]|(~a[0])) ; 
b[2] = a[2] ^ (a[0]|(~a[1])) ; 

a[0] = b[0] ; a[1] = b[1] ; a[2] = b[2] ;
}


void theta(word32 *a)    /* the linear step */
{
word32 b[3];

b[0] = a[0] ^  (a[0]>>16) ^ (a[1]<<16) ^     (a[1]>>16) ^ (a[2]<<16) ^
			   (a[1]>>24) ^ (a[2]<<8)  ^     (a[2]>>8)  ^ (a[0]<<24) ^
			   (a[2]>>16) ^ (a[0]<<16) ^     (a[2]>>24) ^ (a[0]<<8)  ;
b[1] = a[1] ^  (a[1]>>16) ^ (a[2]<<16) ^     (a[2]>>16) ^ (a[0]<<16) ^
			   (a[2]>>24) ^ (a[0]<<8)  ^     (a[0]>>8)  ^ (a[1]<<24) ^
			   (a[0]>>16) ^ (a[1]<<16) ^     (a[0]>>24) ^ (a[1]<<8)  ;
b[2] = a[2] ^  (a[2]>>16) ^ (a[0]<<16) ^     (a[0]>>16) ^ (a[1]<<16) ^
			   (a[0]>>24) ^ (a[1]<<8)  ^     (a[1]>>8)  ^ (a[2]<<24) ^
			   (a[1]>>16) ^ (a[2]<<16) ^     (a[1]>>24) ^ (a[2]<<8)  ;

a[0] = b[0] ;      a[1] = b[1] ;      a[2] = b[2] ;
}

void pi_1(word32 *a)   
{
a[0] = (a[0]>>10) ^ (a[0]<<22);  
a[2] = (a[2]<<1)  ^ (a[2]>>31);
}

void pi_2(word32 *a)   
{
a[0] = (a[0]<<1)  ^ (a[0]>>31);
a[2] = (a[2]>>10) ^ (a[2]<<22);
}

void rho(word32 *a)    /* the round function       */
{
theta(a) ; 
pi_1(a) ; 
gamma(a) ; 
pi_2(a) ;
}

void rndcon_gen(word32 strt,word32 *rtab)
{                           /* generates the round constants */
int i ;

for(i=0 ; i<=NMBR ; i++ )
   {
   rtab[i] = strt ;
   strt <<= 1 ; 
   if( strt&0x10000 ) strt ^= 0x11011 ;
   }
}

void threeway_encrypt(word32 *a, word32 *k)
{
int i ;
word32 rcon[NMBR+1] ;

rndcon_gen(STRT_E,rcon) ; 
for( i=0 ; i<NMBR ; i++ )   
   {
   a[0] ^= k[0] ^ (rcon[i]<<16) ; 
   a[1] ^= k[1] ; 
   a[2] ^= k[2] ^ rcon[i] ;
   rho(a) ;
   }
a[0] ^= k[0] ^ (rcon[NMBR]<<16) ; 
a[1] ^= k[1] ; 
a[2] ^= k[2] ^ rcon[NMBR] ;
theta(a) ;
}


void threeway_decrypt(word32 *a, word32 *k)
{             
int i ;
word32 ki[3] ;          /* the `inverse' key             */
word32 rcon[NMBR+1] ;   /* the `inverse' round constants */

ki[0] = k[0] ; ki[1] = k[1] ; ki[2] = k[2] ; 
theta(ki) ;
mu(ki) ;

rndcon_gen(STRT_D,rcon) ; 

mu(a) ;
for( i=0 ; i<NMBR ; i++ )
   {
   a[0] ^= ki[0] ^ (rcon[i]<<16) ; 
   a[1] ^= ki[1] ; 
   a[2] ^= ki[2] ^ rcon[i] ;
   rho(a) ;
   }
a[0] ^= ki[0] ^ (rcon[NMBR]<<16) ; 
a[1] ^= ki[1] ; 
a[2] ^= ki[2] ^ rcon[NMBR] ;
theta(a) ;
mu(a) ;
}

//#ifdef TEST
//#include <stdio.h>
//#include <stdlib.h>
//#define RAND32 ((word32)rand() << 17 ^ (word32)rand() << 9 ^ rand())
//
//void printvec(word32 *a)
//{
//#ifdef __alpha
//printf("%08x %08x %08x\n",a[2],a[1],a[0]) ;
//#else
//printf("%08lx %08lx %08lx\n",a[2],a[1],a[0]) ;
//#endif
//}
//
//void main()
//{
//word32 vector[3], key[3],plain[3];
//int i,j;
//
//printf("3-way test run\n");
//for (i = 0; i < 10; i++) {
// for (j = 0; j < 3; j++) {
//    key[j] = RAND32;
//    plain[j]=vector[j] = RAND32;
//    }
//
// printf("%3d\r", i);
//
// fflush(stdout);
//
// for (j = 0; j < 100; j++)
//  encrypt(vector,key);
// for (j = 0; j < 100; j++)
//  decrypt(vector,key);
//
// if (vector[0] != plain[0] || vector[1] != plain[1] ||
//     vector[2] != plain[2] ) {
//      fprintf(stderr, "\nError! i = %d\n", i);
//      exit(1);
//     }
// }
//        printf("All tests passed.\n");
//  key[0]=4; key[1]=5; key[2]=6;
//  vector[0]=1; vector[1]=2; vector[2]=3;
//  encrypt(vector,key);
//  printvec(vector);
//}
//#endif

#undef n2l
#define n2l(c,l)        (l =((unsigned int)(*((c)++)))<<24L, \
                         l|=((unsigned int)(*((c)++)))<<16L, \
                         l|=((unsigned int)(*((c)++)))<< 8L, \
                         l|=((unsigned int)(*((c)++))))

#undef l2n
#define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)     )&0xff))

void _threeway_encrypt(unsigned char data[12], unsigned char out[12], unsigned char key[12])
{
	word32 _key[3];
	n2l(key, _key[0]);
	n2l(key, _key[1]);
	n2l(key, _key[2]);

	word32 _data[3];
	n2l(data, _data[0]);
	n2l(data, _data[1]);
	n2l(data, _data[2]);

	threeway_encrypt(_data, _key);

	unsigned char *pout = out;
	l2n(_data[0], pout);
	l2n(_data[1], pout);
	l2n(_data[2], pout);
}

void _threeway_decrypt(unsigned char data[12], unsigned char out[12], unsigned char key[12])
{
	word32 _key[3];
	n2l(key, _key[0]);
	n2l(key, _key[1]);
	n2l(key, _key[2]);

	word32 _data[3];
	n2l(data, _data[0]);
	n2l(data, _data[1]);
	n2l(data, _data[2]);

	threeway_decrypt(_data, _key);

	unsigned char *pout = out;
	l2n(_data[0], pout);
	l2n(_data[1], pout);
	l2n(_data[2], pout);
}

int _threeway_crypt_cbc(int mode,
                    int length,
                    unsigned char iv[12],
                    unsigned char *input,
                    unsigned char *output,
					unsigned char key[12])
{
    int i;
    unsigned char temp[12];

    if( length % 12 )
        return 0;//( POLARSSL_ERR_AES_INVALID_INPUT_LENGTH );

    if( mode == THREEWAY_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 12 );
			_threeway_decrypt((unsigned char *)input, output, key);

            for( i = 0; i < 12; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 12 );

            input  += 12;
            output += 12;
            length -= 12;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 12; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

			_threeway_encrypt(output, output, key);
            memcpy( iv, output, 12 );

            input  += 12;
            output += 12;
            length -= 12;
        }
    }

    return( 0 );
}

int _threeway_crypt_cfb96(int mode,
					   int length,
					   int *iv_off,
					   unsigned char iv[12],
					   unsigned char *input,
					   unsigned char *output,
					   unsigned char key[12])
{
	int c;
	int n = *iv_off;

	if( mode == THREEWAY_DECRYPT )
	{
		while( length-- )
		{
			if( n == 0 )
				_threeway_encrypt(iv, iv, key);

			c = *input++;
			*output++ = (unsigned char)( c ^ iv[n] );
			iv[n] = (unsigned char) c;

			n = (n + 1) % 12;
		}
	}
	else
	{
		while( length-- )
		{
			if( n == 0 )
				_threeway_encrypt(iv, iv, key);

			iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

			n = (n + 1) % 12;
		}
	}

	*iv_off = n;

	return( 0 );
}

int _threeway_crypt_ofb(int length,
                       int *iv_off,       //(updated after use)
                       unsigned char iv[12], //(updated after use)
                       unsigned char *input,
                       unsigned char *output,
					   unsigned char key[12])
{
	unsigned int n = *iv_off; 

	while (length--) {  
		if (n == 0) {
			_threeway_encrypt(iv, iv, key);
		}  
		*(output++) = *(input++) ^ iv[n];  
		n = (n + 1) % 12;  
	}  

	*iv_off = n;

	return 0;
}

int _threeway_crypt_ctr( int length,
                       int *nc_off,
                       unsigned char nonce_counter[12],
                       unsigned char stream_block[12],
                       unsigned char *input,
                       unsigned char *output,
					   unsigned char key[12])
{
    int n = *nc_off;
	unsigned char temp[12];

    while( length-- )
    {
        if( n == 0 ) {
			_threeway_encrypt(nonce_counter, temp, key);

            for( int i = 12; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        int c = *input++;
        *output++ = (unsigned char)( c ^ temp[n] );

        n = (n + 1) % 12;
    }

    *nc_off = n;

    return( 0 );
}