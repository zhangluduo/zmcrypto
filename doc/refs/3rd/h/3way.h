
#if !defined _THREEWAY_H
#define _THREEWAY_H

	//#ifdef __alpha  /* Any other 64-bit machines? */
	typedef unsigned int word32;
	//#else
	//typedef unsigned long word32;
	//#endif

#define THREEWAY_ENCRYPT 1
#define THREEWAY_DECRYPT 0

void threeway_encrypt(word32 *data, word32 key[3]);
void threeway_decrypt(word32 *data, word32 key[3]);

/*
Add by Zhang Luduo(http://www.ZhangLuduo.com/)
2014-11-18
*/

void _threeway_encrypt(unsigned char data[12], unsigned char out[12], unsigned char key[12]);
void _threeway_decrypt(unsigned char data[12], unsigned char out[12], unsigned char key[12]);

int _threeway_crypt_cbc(int mode,
                    int length,
                    unsigned char iv[12],
                    unsigned char *input,
                    unsigned char *output,
					unsigned char key[12]);

int _threeway_crypt_cfb96(int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[12],
                       unsigned char *input,
                       unsigned char *output,
					   unsigned char key[12]);


int _threeway_crypt_ofb(int length,
                       int *iv_off,       //(updated after use)
                       unsigned char iv[12], //(updated after use)
                       unsigned char *input,
                       unsigned char *output,
					   unsigned char key[12]);

int _threeway_crypt_ctr( int length,
                       int *nc_off,
                       unsigned char nonce_counter[12],
                       unsigned char stream_block[12],
                       unsigned char *input,
                       unsigned char *output,
					   unsigned char key[12]);

#endif