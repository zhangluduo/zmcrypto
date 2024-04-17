
#include "idea.h"

#undef n2s
#define n2s(c,l)	(l =((IDEA_INT)(*((c)++)))<< 8L, \
			 l|=((IDEA_INT)(*((c)++)))      )

#undef n2l
#define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24L, \
                         l|=((unsigned long)(*((c)++)))<<16L, \
                         l|=((unsigned long)(*((c)++)))<< 8L, \
                         l|=((unsigned long)(*((c)++))))

#undef l2n
#define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)     )&0xff))

#define E_IDEA(num) \
	x1&=0xffff; \
	idea_mul(x1,x1,*p,ul); p++; \
	x2+= *(p++); \
	x3+= *(p++); \
	x4&=0xffff; \
	idea_mul(x4,x4,*p,ul); p++; \
	t0=(x1^x3)&0xffff; \
	idea_mul(t0,t0,*p,ul); p++; \
	t1=(t0+(x2^x4))&0xffff; \
	idea_mul(t1,t1,*p,ul); p++; \
	t0+=t1; \
	x1^=t1; \
	x4^=t0; \
	ul=x2^t0; /* do the swap to x3 */ \
	x2=x3^t1; \
	x3=ul;

/* The new form of this macro (check if the a*b == 0) was suggested by 
 * Colin Plumb <colin@nyx10.cs.du.edu> */
/* Removal of the inner if from from Wei Dai 24/4/96 */
#define idea_mul(r,a,b,ul) \
ul=(unsigned long)a*b; \
if (ul != 0) \
	{ \
	r=(ul&0xffff)-(ul>>16); \
	r-=((r)>>16); \
	} \
else \
	r=(-(int)a-b+1); /* assuming a or b is 0 and in range */ 

/* NOTE - c is not incremented as per n2l */
#define n2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))    ; \
			case 7: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 6: l2|=((unsigned long)(*(--(c))))<<16; \
			case 5: l2|=((unsigned long)(*(--(c))))<<24; \
			case 4: l1 =((unsigned long)(*(--(c))))    ; \
			case 3: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 2: l1|=((unsigned long)(*(--(c))))<<16; \
			case 1: l1|=((unsigned long)(*(--(c))))<<24; \
				} \
			}

/* NOTE - c is not incremented as per l2n */
#define l2nn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)    )&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
				} \
			}

/* taken directly from the 'paper' I'll have a look at it later */
static IDEA_INT inverse(unsigned int xin)
	{
	long n1,n2,q,r,b1,b2,t;

	if (xin == 0)
		b2=0;
	else
		{
		n1=0x10001;
		n2=xin;
		b2=1;
		b1=0;

		do	{
			r=(n1%n2);
			q=(n1-r)/n2;
			if (r == 0)
				{ if (b2 < 0) b2=0x10001+b2; }
			else
				{
				n1=n2;
				n2=r;
				t=b2;
				b2=b1-q*b2;
				b1=t;
				}
			} while (r != 0);
		}
	return((IDEA_INT)b2);
	}

void idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks)
	{
	int i;
	register IDEA_INT *kt,*kf,r0,r1,r2;

	kt= &(ks->data[0][0]);
	n2s(key,kt[0]); n2s(key,kt[1]); n2s(key,kt[2]); n2s(key,kt[3]);
	n2s(key,kt[4]); n2s(key,kt[5]); n2s(key,kt[6]); n2s(key,kt[7]);

	kf=kt;
	kt+=8;
	for (i=0; i<6; i++)
		{
		r2= kf[1];
		r1= kf[2];
		*(kt++)= ((r2<<9) | (r1>>7))&0xffff;
		r0= kf[3];
		*(kt++)= ((r1<<9) | (r0>>7))&0xffff;
		r1= kf[4];
		*(kt++)= ((r0<<9) | (r1>>7))&0xffff;
		r0= kf[5];
		*(kt++)= ((r1<<9) | (r0>>7))&0xffff;
		r1= kf[6];
		*(kt++)= ((r0<<9) | (r1>>7))&0xffff;
		r0= kf[7];
		*(kt++)= ((r1<<9) | (r0>>7))&0xffff;
		r1= kf[0];
		if (i >= 5) break;
		*(kt++)= ((r0<<9) | (r1>>7))&0xffff;
		*(kt++)= ((r1<<9) | (r2>>7))&0xffff;
		kf+=8;
		}
	}

void idea_set_decrypt_key(const IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk)
	{
	int r;
	register IDEA_INT *tp,t;
	const IDEA_INT *fp;

	tp= &(dk->data[0][0]);
	fp= &(ek->data[8][0]);
	for (r=0; r<9; r++)
		{
		*(tp++)=inverse(fp[0]);
		*(tp++)=((int)(0x10000L-fp[2])&0xffff);
		*(tp++)=((int)(0x10000L-fp[1])&0xffff);
		*(tp++)=inverse(fp[3]);
		if (r == 8) break;
		fp-=6;
		*(tp++)=fp[4];
		*(tp++)=fp[5];
		}

	tp= &(dk->data[0][0]);
	t=tp[1];
	tp[1]=tp[2];
	tp[2]=t;

	t=tp[49];
	tp[49]=tp[50];
	tp[50]=t;
	}

void idea_encrypt(unsigned long *d, IDEA_KEY_SCHEDULE *key);
void idea_ecb_encrypt(const unsigned char *in, unsigned char *out,
	     IDEA_KEY_SCHEDULE *ks)
	{
	unsigned long l0,l1,d[2];

	n2l(in,l0); d[0]=l0;
	n2l(in,l1); d[1]=l1;
	idea_encrypt(d,ks);
	l0=d[0]; l2n(l0,out);
	l1=d[1]; l2n(l1,out);
	l0=l1=d[0]=d[1]=0;
	}

void idea_encrypt(unsigned long *d, IDEA_KEY_SCHEDULE *key)
	{
	register IDEA_INT *p;
	register unsigned long x1,x2,x3,x4,t0,t1,ul;

	x2=d[0];
	x1=(x2>>16);
	x4=d[1];
	x3=(x4>>16);

	p= &(key->data[0][0]);

	E_IDEA(0);
	E_IDEA(1);
	E_IDEA(2);
	E_IDEA(3);
	E_IDEA(4);
	E_IDEA(5);
	E_IDEA(6);
	E_IDEA(7);

	x1&=0xffff;
	idea_mul(x1,x1,*p,ul); p++;

	t0= x3+ *(p++);
	t1= x2+ *(p++);

	x4&=0xffff;
	idea_mul(x4,x4,*p,ul);

	d[0]=(t0&0xffff)|((x1&0xffff)<<16);
	d[1]=(x4&0xffff)|((t1&0xffff)<<16);
	}

void idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
	     IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int encrypt)
	{
	register unsigned long tin0,tin1;
	register unsigned long tout0,tout1,xor0,xor1;
	register long l=length;
	unsigned long tin[2];

	if (encrypt)
		{
		n2l(iv,tout0);
		n2l(iv,tout1);
		iv-=8;
		for (l-=8; l>=0; l-=8)
			{
			n2l(in,tin0);
			n2l(in,tin1);
			tin0^=tout0;
			tin1^=tout1;
			tin[0]=tin0;
			tin[1]=tin1;
			idea_encrypt(tin,ks);
			tout0=tin[0]; l2n(tout0,out);
			tout1=tin[1]; l2n(tout1,out);
			}
		if (l != -8)
			{
			n2ln(in,tin0,tin1,l+8);
			tin0^=tout0;
			tin1^=tout1;
			tin[0]=tin0;
			tin[1]=tin1;
			idea_encrypt(tin,ks);
			tout0=tin[0]; l2n(tout0,out);
			tout1=tin[1]; l2n(tout1,out);
			}
		l2n(tout0,iv);
		l2n(tout1,iv);
		}
	else
		{
		n2l(iv,xor0);
		n2l(iv,xor1);
		iv-=8;
		for (l-=8; l>=0; l-=8)
			{
			n2l(in,tin0); tin[0]=tin0;
			n2l(in,tin1); tin[1]=tin1;
			idea_encrypt(tin,ks);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2n(tout0,out);
			l2n(tout1,out);
			xor0=tin0;
			xor1=tin1;
			}
		if (l != -8)
			{
			n2l(in,tin0); tin[0]=tin0;
			n2l(in,tin1); tin[1]=tin1;
			idea_encrypt(tin,ks);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2nn(tout0,tout1,out,l+8);
			xor0=tin0;
			xor1=tin1;
			}
		l2n(xor0,iv);
		l2n(xor1,iv);
		}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
	}

/* The input and output encrypted as though 64bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */

void idea_cfb64_encrypt(const unsigned char *in, unsigned char *out,
			long length, IDEA_KEY_SCHEDULE *schedule,
			unsigned char *ivec, int *num, int encrypt)
	{
	register unsigned long v0,v1,t;
	register int n= *num;
	register long l=length;
	unsigned long ti[2];
	unsigned char *iv,c,cc;

	iv=(unsigned char *)ivec;
	if (encrypt)
		{
		while (l--)
			{
			if (n == 0)
				{
				n2l(iv,v0); ti[0]=v0;
				n2l(iv,v1); ti[1]=v1;
				idea_encrypt((unsigned long *)ti,schedule);
				iv=(unsigned char *)ivec;
				t=ti[0]; l2n(t,iv);
				t=ti[1]; l2n(t,iv);
				iv=(unsigned char *)ivec;
				}
			c= *(in++)^iv[n];
			*(out++)=c;
			iv[n]=c;
			n=(n+1)&0x07;
			}
		}
	else
		{
		while (l--)
			{
			if (n == 0)
				{
				n2l(iv,v0); ti[0]=v0;
				n2l(iv,v1); ti[1]=v1;
				idea_encrypt((unsigned long *)ti,schedule);
				iv=(unsigned char *)ivec;
				t=ti[0]; l2n(t,iv);
				t=ti[1]; l2n(t,iv);
				iv=(unsigned char *)ivec;
				}
			cc= *(in++);
			c=iv[n];
			iv[n]=cc;
			*(out++)=c^cc;
			n=(n+1)&0x07;
			}
		}
	v0=v1=ti[0]=ti[1]=t=c=cc=0;
	*num=n;
	}

/* The input and output encrypted as though 64bit ofb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */

void idea_ofb64_encrypt(const unsigned char *in, unsigned char *out,
			long length, IDEA_KEY_SCHEDULE *schedule,
			unsigned char *ivec, int *num)
	{
	register unsigned long v0,v1,t;
	register int n= *num;
	register long l=length;
	unsigned char d[8];
	register char *dp;
	unsigned long ti[2];
	unsigned char *iv;
	int save=0;

	iv=(unsigned char *)ivec;
	n2l(iv,v0);
	n2l(iv,v1);
	ti[0]=v0;
	ti[1]=v1;
	dp=(char *)d;
	l2n(v0,dp);
	l2n(v1,dp);
	while (l--)
		{
		if (n == 0)
			{
			idea_encrypt((unsigned long *)ti,schedule);
			dp=(char *)d;
			t=ti[0]; l2n(t,dp);
			t=ti[1]; l2n(t,dp);
			save++;
			}
		*(out++)= *(in++)^d[n];
		n=(n+1)&0x07;
		}
	if (save)
		{
		v0=ti[0];
		v1=ti[1];
		iv=(unsigned char *)ivec;
		l2n(v0,iv);
		l2n(v1,iv);
		}
	t=v0=v1=ti[0]=ti[1]=0;
	*num=n;
	}

// Add by Zhang Luduo, 2014-11-12
// 在这个函数中, 主要的问题是unsigned char和unsigned long间的转换
void idea_encrypt_ctr( int length,
                       int *nc_off,
                       unsigned char nonce_counter[8],
                       const unsigned char *in,
                       unsigned char *out,
					   IDEA_KEY_SCHEDULE *ks)
	{
	register unsigned long v0,v1,t;
	register int n= *nc_off;
	register long l=length;
	unsigned char d[8];
	register char *dp;
	unsigned long ti[2];
	unsigned char *iv;
	int save=0;

	iv=(unsigned char *)nonce_counter;
	n2l(iv,v0);
	n2l(iv,v1);
	ti[0]=v0;
	ti[1]=v1;

	while (l--)
		{
		if (n == 0)
			{
			idea_encrypt((unsigned long *)ti,ks);

            for( int i = 8; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;



			dp=(char *)d;
			t=ti[0]; l2n(t,dp);
			t=ti[1]; l2n(t,dp);

			iv=(unsigned char *)nonce_counter;
			n2l(iv,v0);
			n2l(iv,v1);
			ti[0]=v0;
			ti[1]=v1;

			save++;


			}
		*(out++)= *(in++)^d[n];
		n=(n+1)&0x07;
		}

	*nc_off=n;
	}