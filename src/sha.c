/*
 * sha.c: routines to compute SHA-1/256/384/512 digests
 *
 * Ref: NIST FIPS PUB 180-2 Secure Hash Standard
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 2.2
 * Sun Nov 16 01:54:00 MST 2003
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sha.h"

#define SHR(x, n)	( (x) >> (n) )
#define ROTR(x, n)	( ( (x) >> (n) ) | ( (x) << (32 - (n)) ) )
#define ROTL(x, n)	( ( (x) << (n) ) | ( (x) >> (32 - (n)) ) )

#define Ch(x, y, z)	( (z) ^ ( (x) & ( (y) ^ (z) ) ) )
#define Parity(x, y, z)	( (x) ^ (y) ^ (z) )
#define Maj(x, y, z)	( ( (x) & (y) ) | ( (z) & ( (x) | (y) ) ) )

#define SIGMA0(x)	( ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22) )
#define SIGMA1(x)	( ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25) )
#define sigma0(x)	( ROTR(x,  7) ^ ROTR(x, 18) ^  SHR(x,  3) )
#define sigma1(x)	( ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10) )

#define SETBIT(str, pos)	str[(pos) >> 3] |=  (0x01 << (7 - (pos) % 8))
#define CLRBIT(str, pos)	str[(pos) >> 3] &= ~(0x01 << (7 - (pos) % 8))
#define BYTECNT(bitcnt)		(1 + (((bitcnt) - 1) >> 3))

#define K11	0x5a827999UL
#define K12	0x6ed9eba1UL
#define K13	0x8f1bbcdcUL
#define K14	0xca62c1d6UL

static unsigned long K256[64] =
{
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
	0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
	0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
	0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
	0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
	0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
	0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static unsigned long H01[5] =
{
	0x67452301UL, 0xefcdab89UL, 0x98badcfeUL,
	0x10325476UL, 0xc3d2e1f0UL
};

static unsigned long H0256[8] =
{
	0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
	0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

#ifdef SHA_BIG_ENDIAN
	#define ul2mem(mem, ul) memcpy(mem, &(ul), 4)
#else

static void ul2mem(mem, ul)		/* endian-neutral */
unsigned char *mem;
unsigned long ul;
{
	int i;

	for (i = 0; i < 4; i++)
		*mem++ = SHR(ul, 24 - i * 8) & 0xff;
}

#endif

static void sha1(p, block)
SHA *p;
unsigned char *block;
{
	unsigned long a, b, c, d, e;
	static unsigned long W[16];

#ifdef SHA_BIG_ENDIAN
	memcpy(W, block, 64);
#else

	int t;
	unsigned long *q;
	for (t = 0, q = W; t < 16; t++, q++) {
		*q = *block++; *q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++; *q = (*q << 8) + *block++;
	}

#endif

/*
 * Use SHA-1 "alternate" method from FIPS PUB 180-2 (ref. 6.1.3)
 *
 * To improve performance, unroll the loop and consolidate
 * assignments by changing the roles of the variables "a"
 * through "e" at each step.  Note that the variable "T" is
 * no longer needed.
 *
 */

#define Pa Parity
#define Ma Maj

a = p->H[0]; b = p->H[1]; c = p->H[2]; d = p->H[3]; e = p->H[4];
e+=ROTL(a,5)+Ch(b,c,d)+K11+W[0];b=ROTL(b,30);
d+=ROTL(e,5)+Ch(a,b,c)+K11+W[1];a=ROTL(a,30);
c+=ROTL(d,5)+Ch(e,a,b)+K11+W[2];e=ROTL(e,30);
b+=ROTL(c,5)+Ch(d,e,a)+K11+W[3];d=ROTL(d,30);
a+=ROTL(b,5)+Ch(c,d,e)+K11+W[4];c=ROTL(c,30);
e+=ROTL(a,5)+Ch(b,c,d)+K11+W[5];b=ROTL(b,30);
d+=ROTL(e,5)+Ch(a,b,c)+K11+W[6];a=ROTL(a,30);
c+=ROTL(d,5)+Ch(e,a,b)+K11+W[7];e=ROTL(e,30);
b+=ROTL(c,5)+Ch(d,e,a)+K11+W[8];d=ROTL(d,30);
a+=ROTL(b,5)+Ch(c,d,e)+K11+W[9];c=ROTL(c,30);
e+=ROTL(a,5)+Ch(b,c,d)+K11+W[10];b=ROTL(b,30);
d+=ROTL(e,5)+Ch(a,b,c)+K11+W[11];a=ROTL(a,30);
c+=ROTL(d,5)+Ch(e,a,b)+K11+W[12];e=ROTL(e,30);
b+=ROTL(c,5)+Ch(d,e,a)+K11+W[13];d=ROTL(d,30);
a+=ROTL(b,5)+Ch(c,d,e)+K11+W[14];c=ROTL(c,30);
e+=ROTL(a,5)+Ch(b,c,d)+K11+W[15];b=ROTL(b,30);
d+=ROTL(e,5)+Ch(a,b,c)+K11+(W[0]=ROTL(W[13]^W[8]^W[2]^W[0],1));a=ROTL(a,30);
c+=ROTL(d,5)+Ch(e,a,b)+K11+(W[1]=ROTL(W[14]^W[9]^W[3]^W[1],1));e=ROTL(e,30);
b+=ROTL(c,5)+Ch(d,e,a)+K11+(W[2]=ROTL(W[15]^W[10]^W[4]^W[2],1));d=ROTL(d,30);
a+=ROTL(b,5)+Ch(c,d,e)+K11+(W[3]=ROTL(W[0]^W[11]^W[5]^W[3],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K12+(W[4]=ROTL(W[1]^W[12]^W[6]^W[4],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K12+(W[5]=ROTL(W[2]^W[13]^W[7]^W[5],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K12+(W[6]=ROTL(W[3]^W[14]^W[8]^W[6],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K12+(W[7]=ROTL(W[4]^W[15]^W[9]^W[7],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K12+(W[8]=ROTL(W[5]^W[0]^W[10]^W[8],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K12+(W[9]=ROTL(W[6]^W[1]^W[11]^W[9],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K12+(W[10]=ROTL(W[7]^W[2]^W[12]^W[10],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K12+(W[11]=ROTL(W[8]^W[3]^W[13]^W[11],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K12+(W[12]=ROTL(W[9]^W[4]^W[14]^W[12],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K12+(W[13]=ROTL(W[10]^W[5]^W[15]^W[13],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K12+(W[14]=ROTL(W[11]^W[6]^W[0]^W[14],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K12+(W[15]=ROTL(W[12]^W[7]^W[1]^W[15],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K12+(W[0]=ROTL(W[13]^W[8]^W[2]^W[0],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K12+(W[1]=ROTL(W[14]^W[9]^W[3]^W[1],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K12+(W[2]=ROTL(W[15]^W[10]^W[4]^W[2],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K12+(W[3]=ROTL(W[0]^W[11]^W[5]^W[3],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K12+(W[4]=ROTL(W[1]^W[12]^W[6]^W[4],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K12+(W[5]=ROTL(W[2]^W[13]^W[7]^W[5],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K12+(W[6]=ROTL(W[3]^W[14]^W[8]^W[6],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K12+(W[7]=ROTL(W[4]^W[15]^W[9]^W[7],1));c=ROTL(c,30);
e+=ROTL(a,5)+Ma(b,c,d)+K13+(W[8]=ROTL(W[5]^W[0]^W[10]^W[8],1));b=ROTL(b,30);
d+=ROTL(e,5)+Ma(a,b,c)+K13+(W[9]=ROTL(W[6]^W[1]^W[11]^W[9],1));a=ROTL(a,30);
c+=ROTL(d,5)+Ma(e,a,b)+K13+(W[10]=ROTL(W[7]^W[2]^W[12]^W[10],1));e=ROTL(e,30);
b+=ROTL(c,5)+Ma(d,e,a)+K13+(W[11]=ROTL(W[8]^W[3]^W[13]^W[11],1));d=ROTL(d,30);
a+=ROTL(b,5)+Ma(c,d,e)+K13+(W[12]=ROTL(W[9]^W[4]^W[14]^W[12],1));c=ROTL(c,30);
e+=ROTL(a,5)+Ma(b,c,d)+K13+(W[13]=ROTL(W[10]^W[5]^W[15]^W[13],1));b=ROTL(b,30);
d+=ROTL(e,5)+Ma(a,b,c)+K13+(W[14]=ROTL(W[11]^W[6]^W[0]^W[14],1));a=ROTL(a,30);
c+=ROTL(d,5)+Ma(e,a,b)+K13+(W[15]=ROTL(W[12]^W[7]^W[1]^W[15],1));e=ROTL(e,30);
b+=ROTL(c,5)+Ma(d,e,a)+K13+(W[0]=ROTL(W[13]^W[8]^W[2]^W[0],1));d=ROTL(d,30);
a+=ROTL(b,5)+Ma(c,d,e)+K13+(W[1]=ROTL(W[14]^W[9]^W[3]^W[1],1));c=ROTL(c,30);
e+=ROTL(a,5)+Ma(b,c,d)+K13+(W[2]=ROTL(W[15]^W[10]^W[4]^W[2],1));b=ROTL(b,30);
d+=ROTL(e,5)+Ma(a,b,c)+K13+(W[3]=ROTL(W[0]^W[11]^W[5]^W[3],1));a=ROTL(a,30);
c+=ROTL(d,5)+Ma(e,a,b)+K13+(W[4]=ROTL(W[1]^W[12]^W[6]^W[4],1));e=ROTL(e,30);
b+=ROTL(c,5)+Ma(d,e,a)+K13+(W[5]=ROTL(W[2]^W[13]^W[7]^W[5],1));d=ROTL(d,30);
a+=ROTL(b,5)+Ma(c,d,e)+K13+(W[6]=ROTL(W[3]^W[14]^W[8]^W[6],1));c=ROTL(c,30);
e+=ROTL(a,5)+Ma(b,c,d)+K13+(W[7]=ROTL(W[4]^W[15]^W[9]^W[7],1));b=ROTL(b,30);
d+=ROTL(e,5)+Ma(a,b,c)+K13+(W[8]=ROTL(W[5]^W[0]^W[10]^W[8],1));a=ROTL(a,30);
c+=ROTL(d,5)+Ma(e,a,b)+K13+(W[9]=ROTL(W[6]^W[1]^W[11]^W[9],1));e=ROTL(e,30);
b+=ROTL(c,5)+Ma(d,e,a)+K13+(W[10]=ROTL(W[7]^W[2]^W[12]^W[10],1));d=ROTL(d,30);
a+=ROTL(b,5)+Ma(c,d,e)+K13+(W[11]=ROTL(W[8]^W[3]^W[13]^W[11],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K14+(W[12]=ROTL(W[9]^W[4]^W[14]^W[12],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K14+(W[13]=ROTL(W[10]^W[5]^W[15]^W[13],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K14+(W[14]=ROTL(W[11]^W[6]^W[0]^W[14],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K14+(W[15]=ROTL(W[12]^W[7]^W[1]^W[15],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K14+(W[0]=ROTL(W[13]^W[8]^W[2]^W[0],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K14+(W[1]=ROTL(W[14]^W[9]^W[3]^W[1],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K14+(W[2]=ROTL(W[15]^W[10]^W[4]^W[2],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K14+(W[3]=ROTL(W[0]^W[11]^W[5]^W[3],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K14+(W[4]=ROTL(W[1]^W[12]^W[6]^W[4],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K14+(W[5]=ROTL(W[2]^W[13]^W[7]^W[5],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K14+(W[6]=ROTL(W[3]^W[14]^W[8]^W[6],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K14+(W[7]=ROTL(W[4]^W[15]^W[9]^W[7],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K14+(W[8]=ROTL(W[5]^W[0]^W[10]^W[8],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K14+(W[9]=ROTL(W[6]^W[1]^W[11]^W[9],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K14+(W[10]=ROTL(W[7]^W[2]^W[12]^W[10],1));c=ROTL(c,30);
e+=ROTL(a,5)+Pa(b,c,d)+K14+(W[11]=ROTL(W[8]^W[3]^W[13]^W[11],1));b=ROTL(b,30);
d+=ROTL(e,5)+Pa(a,b,c)+K14+(W[12]=ROTL(W[9]^W[4]^W[14]^W[12],1));a=ROTL(a,30);
c+=ROTL(d,5)+Pa(e,a,b)+K14+(W[13]=ROTL(W[10]^W[5]^W[15]^W[13],1));e=ROTL(e,30);
b+=ROTL(c,5)+Pa(d,e,a)+K14+(W[14]=ROTL(W[11]^W[6]^W[0]^W[14],1));d=ROTL(d,30);
a+=ROTL(b,5)+Pa(c,d,e)+K14+(W[15]=ROTL(W[12]^W[7]^W[1]^W[15],1));c=ROTL(c,30);
p->H[0] += a; p->H[1] += b; p->H[2] += c; p->H[3] += d; p->H[4] += e;
}

static void sha256(p, block)
SHA *p;
unsigned char *block;
{
	int t;
	unsigned long a, b, c, d, e, f, g, h, T1, T2;
	static unsigned long W[64];

#ifdef SHA_BIG_ENDIAN
	memcpy(W, block, 64);
#else

	unsigned long *q;
	for (t = 0, q = W; t < 16; t++, q++) {
		*q = *block++; *q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++; *q = (*q << 8) + *block++;
	}

#endif

	for (t = 16; t < 64; t++)
		W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
	a = p->H[0]; b = p->H[1]; c = p->H[2]; d = p->H[3];
	e = p->H[4]; f = p->H[5]; g = p->H[6]; h = p->H[7];
	for (t = 0; t < 64; t++) {
		T1 = h + SIGMA1(e) + Ch(e, f, g) + K256[t] + W[t];
		T2 = SIGMA0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
	}
	p->H[0] += a; p->H[1] += b; p->H[2] += c; p->H[3] += d;
	p->H[4] += e; p->H[5] += f; p->H[6] += g; p->H[7] += h;
}

#ifdef SHA_384_512

#define ROTRQ(x, n)	( ( (x) >> (n) ) | ( (x) << (64 - (n)) ) )
#define SIGMAQ0(x)	( ROTRQ(x, 28) ^ ROTRQ(x, 34) ^ ROTRQ(x, 39) )
#define SIGMAQ1(x)	( ROTRQ(x, 14) ^ ROTRQ(x, 18) ^ ROTRQ(x, 41) )
#define sigmaQ0(x)	( ROTRQ(x,  1) ^ ROTRQ(x,  8) ^   SHR(x,  7) )
#define sigmaQ1(x)	( ROTRQ(x, 19) ^ ROTRQ(x, 61) ^   SHR(x,  6) )

static unsigned long long K512[80] =
{
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static unsigned long long HQ0384[8] =
{
	0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
	0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
	0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

static unsigned long long HQ0512[8] =
{
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

#ifdef SHA_BIG_ENDIAN
#define ull2mem(mem, ull) memcpy(mem, &(ull), 8)
#else
static void ull2mem(mem, ull)		/* endian-neutral */
unsigned char *mem;
unsigned long long ull;
{
	int i;

	for (i = 0; i < 8; i++)
		*mem++ = SHR(ull, 56 - i * 8) & 0xff;
}
#endif

/* strtoull() not always present, so cook up an alternative*/
static unsigned long long hex2ull(s)
char *s;
{
	char str[2] = {0, 0};
	unsigned long long u = 0ULL;

	while ((str[0] = *s++) != '\0')
		u = (u << 4) + strtoul(str, NULL, 16);
	return(u);
}

static void sha512(p, block)
SHA *p;
unsigned char *block;
{
	int t;
	unsigned long long a, b, c, d, e, f, g, h, T1, T2;
	static unsigned long long W[80];

#ifdef SHA_BIG_ENDIAN
	memcpy(W, block, 128);
#else
	unsigned long long *q;
	for (t = 0, q = W; t < 16; t++, q++) {
		*q = *block++; *q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++; *q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++; *q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++; *q = (*q << 8) + *block++;
	}
#endif
	for (t = 16; t < 80; t++)
		W[t] = sigmaQ1(W[t-2]) + W[t-7] + sigmaQ0(W[t-15]) + W[t-16];
	a = p->HQ[0]; b = p->HQ[1]; c = p->HQ[2]; d = p->HQ[3];
	e = p->HQ[4]; f = p->HQ[5]; g = p->HQ[6]; h = p->HQ[7];
	for (t = 0; t < 80; t++) {
		T1 = h + SIGMAQ1(e) + Ch(e, f, g) + K512[t] + W[t];
		T2 = SIGMAQ0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
	}
	p->HQ[0] += a; p->HQ[1] += b; p->HQ[2] += c; p->HQ[3] += d;
	p->HQ[4] += e; p->HQ[5] += f; p->HQ[6] += g; p->HQ[7] += h;
}

#endif	/* #ifdef SHA_384_512 */

static void pad(s)
SHA *s;
{
	unsigned int lenpos, lhpos, llpos;

	lenpos = s->blocksize == SHA1_BLOCK_BITS ? 448 : 896;
	lhpos = s->blocksize == SHA1_BLOCK_BITS ? 56 : 120;
	llpos = s->blocksize == SHA1_BLOCK_BITS ? 60 : 124;
	SETBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt > lenpos)
		if (s->blockcnt == s->blocksize)
			s->sha(s, s->block), s->blockcnt = 0;
		else
			CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt < lenpos)
		CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	if (s->blocksize != SHA1_BLOCK_BITS) {
		ul2mem(s->block + 112, s->lenhh);
		ul2mem(s->block + 116, s->lenhl);
	}
	ul2mem(s->block + lhpos, s->lenlh);
	ul2mem(s->block + llpos, s->lenll);
	s->sha(s, s->block), s->blockcnt = 0;
}

static void digcpy(s)
SHA *s;
{
	unsigned int i;

	if (s->blocksize == SHA1_BLOCK_BITS)
		for (i = 0; i < sizeof(s->H)/sizeof(s->H[0]); i++)
			ul2mem(s->digest + i * sizeof(s->H[0]), s->H[i]);
#ifdef SHA_384_512
	else
		for (i = 0; i < sizeof(s->HQ)/sizeof(s->HQ[0]); i++)
			ull2mem(s->digest + i * sizeof(s->HQ[0]), s->HQ[i]);
#endif
}

SHA *shaopen(alg)
int alg;
{
	SHA *s;

	if ((s = (SHA *) calloc(1, sizeof(SHA))) == NULL)
		return(NULL);
	s->alg = alg;
	if (alg == SHA1) {
		s->sha = sha1;
		memcpy(s->H, H01, sizeof(H01));
		s->blocksize = SHA1_BLOCK_BITS;
		s->digestlen = SHA1_DIGEST_BITS >> 3;
	}
	else if (alg == SHA256) {
		s->sha = sha256;
		memcpy(s->H, H0256, sizeof(H0256));
		s->blocksize = SHA256_BLOCK_BITS;
		s->digestlen = SHA256_DIGEST_BITS >> 3;
	}

#ifdef SHA_384_512

	else if (alg == SHA384) {
		s->sha = sha512;
		memcpy(s->HQ, HQ0384, sizeof(HQ0384));
		s->blocksize = SHA384_BLOCK_BITS;
		s->digestlen = SHA384_DIGEST_BITS >> 3;
	}
	else if (alg == SHA512) {
		s->sha = sha512;
		memcpy(s->HQ, HQ0512, sizeof(HQ0512));
		s->blocksize = SHA512_BLOCK_BITS;
		s->digestlen = SHA512_DIGEST_BITS >> 3;
	}

#endif	/* #ifdef SHA_384_512 */

	else {
		free(s);
		return(NULL);
	}
	return(s);
}

static unsigned long shadirect(bitstr, bitcnt, s)
unsigned char *bitstr;
unsigned long bitcnt;
SHA *s;
{
	unsigned long savecnt = bitcnt;

	while (bitcnt >= s->blocksize) {
		s->sha(s, bitstr);
		bitstr += (s->blocksize >> 3);
		bitcnt -= s->blocksize;
	}
	if (bitcnt > 0) {
		memcpy(s->block, bitstr, BYTECNT(bitcnt));
		s->blockcnt = bitcnt;
	}
	return(savecnt);
}

static unsigned long shabytes(bitstr, bitcnt, s)
unsigned char *bitstr;
unsigned long bitcnt;
SHA *s;
{
	unsigned int offset;
	unsigned int numbits;
	unsigned long savecnt = bitcnt;

	offset = s->blockcnt >> 3;
	if (s->blockcnt + bitcnt >= s->blocksize) {
		numbits = s->blocksize - s->blockcnt;
		memcpy(s->block+offset, bitstr, numbits>>3);
		bitcnt -= numbits;
		bitstr += (numbits >> 3);
		s->sha(s, s->block), s->blockcnt = 0;
		shadirect(bitstr, bitcnt, s);
	}
	else {
		memcpy(s->block+offset, bitstr, BYTECNT(bitcnt));
		s->blockcnt += bitcnt;
	}
	return(savecnt);
}

static unsigned long shabits(bitstr, bitcnt, s)
unsigned char *bitstr;
unsigned long bitcnt;
SHA *s;
{
	unsigned int i;
	unsigned int gap;
	unsigned long numbits;
	static unsigned char buf[1<<12];
	unsigned int bufsize = sizeof(buf);
	unsigned long bufbits = bufsize << 3;
	unsigned int numbytes = BYTECNT(bitcnt);
	unsigned long savecnt = bitcnt;

	gap = 8 - s->blockcnt % 8;
	s->block[s->blockcnt>>3] &= ~0 << gap;
	s->block[s->blockcnt>>3] |= *bitstr >> (8 - gap);
	s->blockcnt += bitcnt < gap ? bitcnt : gap;
	if (bitcnt < gap)
		return(savecnt);
	if (s->blockcnt == s->blocksize)
		s->sha(s, s->block), s->blockcnt = 0;
	if ((bitcnt -= gap) == 0)
		return(savecnt);
	while (numbytes > bufsize) {
		for (i = 0; i < bufsize; i++)
			buf[i] = bitstr[i] << gap | bitstr[i+1] >> (8-gap);
		numbits = bitcnt < bufbits ? bitcnt : bufbits;
		shabytes(buf, numbits, s);
		bitcnt -= numbits, bitstr += bufsize, numbytes -= bufsize;
	}
	for (i = 0; i < numbytes - 1; i++)
		buf[i] = bitstr[i] << gap | bitstr[i+1] >> (8-gap);
	buf[numbytes-1] = bitstr[numbytes-1] << gap;
	shabytes(buf, bitcnt, s);
	return(savecnt);
}

unsigned long shawrite(bitstr, bitcnt, s)
unsigned char *bitstr;
unsigned long bitcnt;
SHA *s;
{
	if (bitcnt == 0)
		return(0);
	s->lenll += bitcnt;
	if (s->lenll < bitcnt) {
		s->lenlh++;
		if (s->lenlh == 0) {
			s->lenhl++;
			if (s->lenhl == 0)
				s->lenhh++;
		}
	}
	if (s->blockcnt == 0)
		return(shadirect(bitstr, bitcnt, s));
	else if (s->blockcnt % 8 == 0)
		return(shabytes(bitstr, bitcnt, s));
	else
		return(shabits(bitstr, bitcnt, s));
}

void shafinish(s)
SHA *s;
{
	pad(s);
}

unsigned char *shadigest(s)
SHA *s;
{
	digcpy(s);
	return(s->digest);
}

char *shahex(s)
SHA *s;
{
	int i;

	digcpy(s);
	s->hex[0] = '\0';
	for (i = 0; i < s->digestlen; i++)
		sprintf(s->hex+i*2, "%02x", s->digest[i]);
	return(s->hex);
}

static char map[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *enc3bytes(b, n)
unsigned char *b;
int n;
{
	unsigned char in[3] = {0, 0, 0};
	static char out[5];

	out[0] = '\0';
	if (n < 1 || n > 3)
		return(out);
	memcpy(in, b, n);
	out[0] = map[in[0] >> 2];
	out[1] = map[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	out[2] = map[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
	out[3] = map[in[2] & 0x3f];
	out[n+1] = '\0';
	return(out);
}

char *shabase64(s)
SHA *s;
{
	int n;
	unsigned char *q;

	digcpy(s);
	s->base64[0] = '\0';
	for (n = s->digestlen, q = s->digest; n > 3; n -= 3, q += 3)
		strcat(s->base64, enc3bytes(q, 3));
	strcat(s->base64, enc3bytes(q, n));
	return(s->base64);
}

SHA *shadup(s)
SHA *s;
{
	SHA *p;

	if ((p = (SHA *) malloc(sizeof(SHA))) == NULL)
		return(NULL);
	memcpy(p, s, sizeof(SHA));
	return(p);
}

int shadump(file, s)
char *file;
SHA *s;
{
	int i;
	FILE *f;

	if (file == NULL || strlen(file) == 0)
		f = stdout;
	else if ((f = fopen(file, "w")) == NULL)
		return(0);
	fprintf(f, "alg:%d\n", s->alg);
	fprintf(f, "H");
	for (i = 0; i < sizeof(s->H)/sizeof(s->H[0]); i++)
		fprintf(f, ":%08lx", s->H[i]);
	fprintf(f, "\n");
	fprintf(f, "block");
	for (i = 0; i < sizeof(s->block); i++)
		fprintf(f, ":%02x", s->block[i]);
	fprintf(f, "\n");
	fprintf(f, "blockcnt:%u\n", s->blockcnt);
	fprintf(f, "lenhh:%lu\n", s->lenhh);
	fprintf(f, "lenhl:%lu\n", s->lenhl);
	fprintf(f, "lenlh:%lu\n", s->lenlh);
	fprintf(f, "lenll:%lu\n", s->lenll);
	if (s->alg == SHA1 || s->alg == SHA256) {
		if (f != stdout)
			fclose(f);
		return(1);
	}

#ifdef SHA_384_512

	fprintf(f, "HQ");
	for (i = 0; i < sizeof(s->HQ)/sizeof(s->HQ[0]); i++)
		fprintf(f, ":%016llx", s->HQ[i]);
	fprintf(f, "\n");

#endif

	if (f != stdout)
		fclose(f);
	return(1);
}

static int match(f, tag)
FILE *f;
char *tag;
{
	static char line[1<<10];

	while (fgets(line, sizeof(line), f) != NULL)
		if (line[0] == '#' || isspace(line[0]))
			continue;
		else
			return(strcmp(strtok(line, ":\n"), tag) == 0);
	return(0);
}

#define TYPE_C 1
#define TYPE_I 2
#define TYPE_L 3
#define TYPE_LL 4

static int loadval(f, tag, type, pval, num, base)
FILE *f;
char *tag;
int type;
void *pval;
int num;
int base;
{
	char *p;

	if (!match(f, tag))
		return(0);
	while (num-- > 0) {
		if ((p = strtok(NULL, ":\n")) == NULL)
			return(0);
		if (type == TYPE_C)
			*((unsigned char *) pval)++ = strtoul(p, NULL, base);
		else if (type == TYPE_I)
			*((unsigned int *) pval)++ = strtoul(p, NULL, base);
		else if (type == TYPE_L)
			*((unsigned long *) pval)++ = strtoul(p, NULL, base);
#ifdef SHA_384_512
		else if (type == TYPE_LL)
			*((unsigned long long *) pval)++ = hex2ull(p);
#endif
		else
			return(0);
	}
	return(1);
}

static SHA *closeall(f, s)
FILE *f;
SHA *s;
{
	if (f != NULL && f != stdin)
		fclose(f);
	if (s != NULL)
		shaclose(s);
	return(NULL);
}

SHA *shaload(file)
char *file;
{
	int alg;
	SHA *s;
	FILE *f;

	if (file == NULL || strlen(file) == 0)
		f = stdin;
	else if ((f = fopen(file, "r")) == NULL)
		return(NULL);
	if (!loadval(f, "alg", TYPE_I, &alg, 1, 10))
		return(closeall(f, NULL));
	if ((s = shaopen(alg)) == NULL)
		return(closeall(f, NULL));
	if (!loadval(f, "H", TYPE_L, s->H, sizeof(s->H)/sizeof(s->H[0]), 16))
		return(closeall(f, s));
	if (!loadval(f, "block", TYPE_C, s->block, s->blocksize>>3, 16))
		return(closeall(f, s));
	if (!loadval(f, "blockcnt", TYPE_I, &s->blockcnt, 1, 10))
		return(closeall(f, s));
	if (!loadval(f, "lenhh", TYPE_L, &s->lenhh, 1, 10))
		return(closeall(f, s));
	if (!loadval(f, "lenhl", TYPE_L, &s->lenhl, 1, 10))
		return(closeall(f, s));
	if (!loadval(f, "lenlh", TYPE_L, &s->lenlh, 1, 10))
		return(closeall(f, s));
	if (!loadval(f, "lenll", TYPE_L, &s->lenll, 1, 10))
		return(closeall(f, s));
	if (alg == SHA1 || alg == SHA256) {
		if (f != stdin)
			fclose(f);
		return(s);
	}

#ifdef SHA_384_512
	if (!loadval(f,"HQ",TYPE_LL,s->HQ,sizeof(s->HQ)/sizeof(s->HQ[0]),16))
		return(closeall(f, s));
#endif

	if (f != stdin)
		fclose(f);
	return(s);
}

int shaclose(s)
SHA *s;
{
	memset(s, 0, sizeof(SHA));
	free(s);
	return(0);
}

static unsigned char *shacomp(alg, fmt, bitstr, bitcnt)
int alg;
int fmt;
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static unsigned char digest[SHA_MAX_HEX_LEN+1];
	unsigned char *ret = digest;

	if ((s = shaopen(alg)) == NULL)
		return(NULL);
	shawrite(bitstr, bitcnt, s);
	shafinish(s);
	if (fmt == SHA_FMT_RAW)
		memcpy(digest, shadigest(s), s->digestlen);
	else if (fmt == SHA_FMT_HEX)
		strcpy((char *) digest, shahex(s));
	else if (fmt == SHA_FMT_BASE64)
		strcpy((char *) digest, shabase64(s));
	else
		ret = NULL;
	shaclose(s);
	return(ret);
}

#define SHA_DIRECT(type, name, alg, fmt) 			\
type name(bitstr, bitcnt)					\
unsigned char *bitstr;						\
unsigned long bitcnt;						\
{								\
	return((type) shacomp(alg, fmt, bitstr, bitcnt));	\
}

SHA_DIRECT(unsigned char *, sha1digest, SHA1, SHA_FMT_RAW)
SHA_DIRECT(char *, sha1hex, SHA1, SHA_FMT_HEX)
SHA_DIRECT(char *, sha1base64, SHA1, SHA_FMT_BASE64)

SHA_DIRECT(unsigned char *, sha256digest, SHA256, SHA_FMT_RAW)
SHA_DIRECT(char *, sha256hex, SHA256, SHA_FMT_HEX)
SHA_DIRECT(char *, sha256base64, SHA256, SHA_FMT_BASE64)

#ifdef SHA_384_512

SHA_DIRECT(unsigned char *, sha384digest, SHA384, SHA_FMT_RAW)
SHA_DIRECT(char *, sha384hex, SHA384, SHA_FMT_HEX)
SHA_DIRECT(char *, sha384base64, SHA384, SHA_FMT_BASE64)

SHA_DIRECT(unsigned char *, sha512digest, SHA512, SHA_FMT_RAW)
SHA_DIRECT(char *, sha512hex, SHA512, SHA_FMT_HEX)
SHA_DIRECT(char *, sha512base64, SHA512, SHA_FMT_BASE64)

#endif	/* #ifdef SHA_384_512 */
