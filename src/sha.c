/*
 * sha.c: routines to compute SHA-1/256/384/512 digests
 *
 * Ref: NIST FIPS PUB 180-2 Secure Hash Standard
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 1.01
 * Fri Oct 24 19:15:26 MST 2003
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha.h"

#define SHR(x, n)	( (x) >> (n) )
#define ROTR(x, n)	( ( (x) >> (n) ) | ( (x) << (32 - (n)) ) )
#define ROTL(x, n)	( ( (x) << (n) ) | ( (x) >> (32 - (n)) ) )


#ifdef SHA_384_512

#define ROTRQ(x, n)	( ( (x) >> (n) ) | ( (x) << (64 - (n)) ) )

#endif	/* #ifdef SHA_384_512 */


#define Ch(x, y, z)	( ( (x) & (y) ) ^ ( ~(x) & (z) ) )
#define Parity(x, y, z)	( (x) ^ (y) ^ (z) )
#define Maj(x, y, z)	( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define SIGMA0(x)	( ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22) )
#define SIGMA1(x)	( ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25) )
#define sigma0(x)	( ROTR(x,  7) ^ ROTR(x, 18) ^  SHR(x,  3) )
#define sigma1(x)	( ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10) )


#ifdef SHA_384_512

#define SIGMAQ0(x)	( ROTRQ(x, 28) ^ ROTRQ(x, 34) ^ ROTRQ(x, 39) )
#define SIGMAQ1(x)	( ROTRQ(x, 14) ^ ROTRQ(x, 18) ^ ROTRQ(x, 41) )
#define sigmaQ0(x)	( ROTRQ(x,  1) ^ ROTRQ(x,  8) ^   SHR(x,  7) )
#define sigmaQ1(x)	( ROTRQ(x, 19) ^ ROTRQ(x, 61) ^   SHR(x,  6) )

#endif	/* #ifdef SHA_384_512 */


static unsigned long K1[80] =
{
	0x5a827999UL, 0x5a827999UL, 0x5a827999UL, 0x5a827999UL,
	0x5a827999UL, 0x5a827999UL, 0x5a827999UL, 0x5a827999UL,
	0x5a827999UL, 0x5a827999UL, 0x5a827999UL, 0x5a827999UL,
	0x5a827999UL, 0x5a827999UL, 0x5a827999UL, 0x5a827999UL,
	0x5a827999UL, 0x5a827999UL, 0x5a827999UL, 0x5a827999UL,
	0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL,
	0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL,
	0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL,
	0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL,
	0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL, 0x6ed9eba1UL,
	0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL,
	0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL,
	0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL,
	0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL,
	0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL, 0x8f1bbcdcUL,
	0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL,
	0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL,
	0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL,
	0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL,
	0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL, 0xca62c1d6UL
};

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


#ifdef SHA_384_512

static unsigned long long K512[80] =
{
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#endif	/* #ifdef SHA_384_512 */


static unsigned long H01[5] =
{
	0x67452301UL,
	0xefcdab89UL,
	0x98badcfeUL,
	0x10325476UL,
	0xc3d2e1f0UL
};

static unsigned long H0256[8] =
{
	0x6a09e667UL,
	0xbb67ae85UL,
	0x3c6ef372UL,
	0xa54ff53aUL,
	0x510e527fUL,
	0x9b05688cUL,
	0x1f83d9abUL,
	0x5be0cd19UL
};


#ifdef SHA_384_512

static unsigned long long HQ0384[8] =
{
	0xcbbb9d5dc1059ed8ULL,
	0x629a292a367cd507ULL,
	0x9159015a3070dd17ULL,
	0x152fecd8f70e5939ULL,
	0x67332667ffc00b31ULL,
	0x8eb44a8768581511ULL,
	0xdb0c2e0d64f98fa7ULL,
	0x47b5481dbefa4fa4ULL
};

static unsigned long long HQ0512[8] =
{
	0x6a09e667f3bcc908ULL,
	0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL,
	0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL,
	0x5be0cd19137e2179ULL
};

#endif	/* #ifdef SHA_384_512 */


#define SETBIT(str, pos)	str[(pos) >> 3] |=  (0x01 << (7 - (pos) % 8))
#define CLRBIT(str, pos)	str[(pos) >> 3] &= ~(0x01 << (7 - (pos) % 8))
#define BYTECNT(bitcnt)		(1 + (((bitcnt) - 1) >> 3))


static void ul2mem(mem, ul)		/* endian-neutral */
unsigned char *mem;
unsigned long ul;
{
	int i;

	for (i = 0; i < 4; i++)
		*mem++ = SHR(ul, 24 - i * 8) & 0xff;
}


#ifdef SHA_384_512

static void ull2mem(mem, ull)		/* endian-neutral */
unsigned char *mem;
unsigned long long ull;
{
	int i;

	for (i = 0; i < 8; i++)
		*mem++ = SHR(ull, 56 - i * 8) & 0xff;
}

#endif	/* #ifdef SHA_384_512 */


static void sha1(p, block)
SHA *p;
unsigned char *block;
{
	int t;
	unsigned long a, b, c, d, e, T;
	static unsigned long W[80];
	unsigned long *q = W;

	for (t = 0; t < 16; t++) {
		*q = *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		q++;
	}
	for (t = 16; t < 80; t++)
		W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
	a = p->H[0];
	b = p->H[1];
	c = p->H[2];
	d = p->H[3];
	e = p->H[4];
	for (t = 0; t < 20; t++) {
		T = ROTL(a, 5) + Ch(b, c, d) + e + K1[t] + W[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;
	}
	for (t = 20; t < 40; t++) {
		T = ROTL(a, 5) + Parity(b, c, d) + e + K1[t] + W[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;
	}
	for (t = 40; t < 60; t++) {
		T = ROTL(a, 5) + Maj(b, c, d) + e + K1[t] + W[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;
	}
	for (t = 60; t < 80; t++) {
		T = ROTL(a, 5) + Parity(b, c, d) + e + K1[t] + W[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;
	}
	p->H[0] += a;
	p->H[1] += b;
	p->H[2] += c;
	p->H[3] += d;
	p->H[4] += e;
}

static void sha256(p, block)
SHA *p;
unsigned char *block;
{
	int t;
	unsigned long a, b, c, d, e, f, g, h, T1, T2;
	static unsigned long W[64];
	unsigned long *q = W;

	for (t = 0; t < 16; t++) {
		*q = *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		q++;
	}
	for (t = 16; t < 64; t++)
		W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
	a = p->H[0];
	b = p->H[1];
	c = p->H[2];
	d = p->H[3];
	e = p->H[4];
	f = p->H[5];
	g = p->H[6];
	h = p->H[7];
	for (t = 0; t < 64; t++) {
		T1 = h + SIGMA1(e) + Ch(e, f, g) + K256[t] + W[t];
		T2 = SIGMA0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	p->H[0] += a;
	p->H[1] += b;
	p->H[2] += c;
	p->H[3] += d;
	p->H[4] += e;
	p->H[5] += f;
	p->H[6] += g;
	p->H[7] += h;
}


#ifdef SHA_384_512

static void sha512(p, block)
SHA *p;
unsigned char *block;
{
	int t;
	unsigned long long a, b, c, d, e, f, g, h, T1, T2;
	static unsigned long long W[80];
	unsigned long long *q = W;

	for (t = 0; t < 16; t++) {
		*q = *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		*q = (*q << 8) + *block++;
		q++;
	}
	for (t = 16; t < 80; t++)
		W[t] = sigmaQ1(W[t-2]) + W[t-7] + sigmaQ0(W[t-15]) + W[t-16];
	a = p->HQ[0];
	b = p->HQ[1];
	c = p->HQ[2];
	d = p->HQ[3];
	e = p->HQ[4];
	f = p->HQ[5];
	g = p->HQ[6];
	h = p->HQ[7];
	for (t = 0; t < 80; t++) {
		T1 = h + SIGMAQ1(e) + Ch(e, f, g) + K512[t] + W[t];
		T2 = SIGMAQ0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	p->HQ[0] += a;
	p->HQ[1] += b;
	p->HQ[2] += c;
	p->HQ[3] += d;
	p->HQ[4] += e;
	p->HQ[5] += f;
	p->HQ[6] += g;
	p->HQ[7] += h;
}

#endif	/* #ifdef SHA_384_512 */


static void pad512(s)
SHA *s;
{
	SETBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt > 448)
		if (s->blockcnt == s->blocksize)
			s->sha(s, s->block), s->blockcnt = 0;
		else
			CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt < 448)
		CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	ul2mem(s->block + 56, s->lenlh);
	ul2mem(s->block + 60, s->lenll);
}

static void putH(s)
SHA *s;
{
	unsigned int i;

	for (i = 0; i < sizeof(s->H)/sizeof(s->H[0]); i++)
		ul2mem(s->digest + i * sizeof(s->H[0]), s->H[i]);
}


#ifdef SHA_384_512

static void pad1024(s)
SHA *s;
{
	SETBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt > 896)
		if (s->blockcnt == s->blocksize)
			s->sha(s, s->block), s->blockcnt = 0;
		else
			CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt < 896)
		CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	ul2mem(s->block + 112, s->lenhh);
	ul2mem(s->block + 116, s->lenhl);
	ul2mem(s->block + 120, s->lenlh);
	ul2mem(s->block + 124, s->lenll);
}

static void putHQ(s)
SHA *s;
{
	unsigned int i;

	for (i = 0; i < sizeof(s->HQ)/sizeof(s->HQ[0]); i++)
		ull2mem(s->digest + i * sizeof(s->HQ[0]), s->HQ[i]);
}

#endif	/* #ifdef SHA_384_512 */


SHA *shaopen(alg)
int alg;
{
	SHA *s;

	if ((s = (SHA *) malloc(sizeof(SHA))) == NULL)
		return(NULL);
	s->lenhh = 0;
	s->lenhl = 0;
	s->lenlh = 0;
	s->lenll = 0;
	s->blockcnt = 0;
	memset(s->H, 0, sizeof(s->H));
	memset(s->digest, 0, sizeof(s->digest));
	if (alg == SHA1) {
		s->sha = sha1;
		s->pad = pad512;
		s->put = putH;
		memcpy(s->H, H01, sizeof(H01));
		s->blocksize = SHA1_BLOCK_BITS;
		s->digestlen = SHA1_DIGEST_BITS >> 3;
		return(s);
	}
	else if (alg == SHA256) {
		s->sha = sha256;
		s->pad = pad512;
		s->put = putH;
		memcpy(s->H, H0256, sizeof(H0256));
		s->blocksize = SHA256_BLOCK_BITS;
		s->digestlen = SHA256_DIGEST_BITS >> 3;
		return(s);
	}


#ifdef SHA_384_512

	else if (alg == SHA384) {
		s->sha = sha512;
		s->pad = pad1024;
		s->put = putHQ;
		memcpy(s->HQ, HQ0384, sizeof(HQ0384));
		s->blocksize = SHA384_BLOCK_BITS;
		s->digestlen = SHA384_DIGEST_BITS >> 3;
		return(s);
	}
	else if (alg == SHA512) {
		s->sha = sha512;
		s->pad = pad1024;
		s->put = putHQ;
		memcpy(s->HQ, HQ0512, sizeof(HQ0512));
		s->blocksize = SHA512_BLOCK_BITS;
		s->digestlen = SHA512_DIGEST_BITS >> 3;
		return(s);
	}

#endif	/* #ifdef SHA_384_512 */


	else {
		free(s);
		return(NULL);
	}
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
	static unsigned char buf[4096];
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
	unsigned long prevll = s->lenll;
	unsigned long prevlh = s->lenlh;
	unsigned long prevhl = s->lenhl;

	if (bitcnt == 0)
		return(0);
	s->lenll += bitcnt;
	if (s->lenll < prevll)
		s->lenlh++;
	if (s->lenlh < prevlh)
		s->lenhl++;
	if (s->lenhl < prevhl)
		s->lenhh++;
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
	s->pad(s);
	s->sha(s, s->block);
	s->put(s);
}

unsigned char *shadigest(s)
SHA *s;
{
	s->put(s);
	return(s->digest);
}

char *shahex(s)
SHA *s;
{
	int i;

	s->put(s);
	s->hex[0] = '\0';
	for (i = 0; i < s->digestlen; i++)
		sprintf(s->hex+i*2, "%02x", s->digest[i]);
	return(s->hex);
}

static char map64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *enc64(b, n)
unsigned char *b;
int n;
{
	unsigned char byte[3] = {0, 0, 0};
	static char str[5];

	str[0] = '\0';
	if (n < 1 || n > 3)
		return(str);
	memcpy(byte, b, n);
	str[0] = map64[byte[0] >> 2];
	str[1] = map64[((byte[0] & 0x03) << 4) | (byte[1] >> 4)];
	str[2] = map64[((byte[1] & 0x0f) << 2) | (byte[2] >> 6)];
	str[3] = map64[byte[2] & 0x3f];
	str[n+1] = '\0';
	return(str);
}

char *shabase64(s)
SHA *s;
{
	int n;
	unsigned char *q;

	s->put(s);
	s->base64[0] = '\0';
	for (n = s->digestlen, q = s->digest; n > 3; n -= 3, q += 3)
		strcat(s->base64, enc64(q, 3));
	strcat(s->base64, enc64(q, n));
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
	int alg;
	FILE *f;

	if ((f = fopen(file, "w")) == NULL)
		return(0);
	if (s->digestlen == SHA1_DIGEST_BITS >> 3)
		alg = SHA1;
	else if (s->digestlen == SHA256_DIGEST_BITS >> 3)
		alg = SHA256;

#ifdef SHA_384_512

	else if (s->digestlen == SHA384_DIGEST_BITS >> 3)
		alg = SHA384;
	else if (s->digestlen == SHA512_DIGEST_BITS >> 3)
		alg = SHA512;

#endif

	else {
		fclose(f);
		return(0);
	}
	fprintf(f, "alg:%d\n", alg);
	fprintf(f, "H");
	for (i = 0; i < sizeof(s->H)/sizeof(s->H[0]); i++)
		fprintf(f, ":%lx", s->H[i]);
	fprintf(f, "\n");
	fprintf(f, "block");
	for (i = 0; i < sizeof(s->block); i++)
		fprintf(f, ":%x", s->block[i]);
	fprintf(f, "\n");
	fprintf(f, "blockcnt:%u\n", s->blockcnt);
	fprintf(f, "lenhh:%lu\n", s->lenhh);
	fprintf(f, "lenhl:%lu\n", s->lenhl);
	fprintf(f, "lenlh:%lu\n", s->lenlh);
	fprintf(f, "lenll:%lu\n", s->lenll);

#ifdef SHA_384_512

	fprintf(f, "HQ");
	for (i = 0; i < sizeof(s->HQ)/sizeof(s->HQ[0]); i++)
		fprintf(f, ":%llx", s->HQ[i]);
	fprintf(f, "\n");

#endif

	fclose(f);
	return(1);
}

#ifdef SHA_384_512

static unsigned long long hex2ull(s)
char *s;
{
	char str[2];
	unsigned long long u = 0ULL;

	str[1] = '\0';
	while ((str[0] = *s++) != 0)
		u = (u << 4) + strtoul(str, NULL, 16);
	return(u);
}

#endif

SHA *shaload(file)
char *file;
{
	int i;
	SHA *s;
	FILE *f;
	static char line[1024];

	if ((f = fopen(file, "r")) == NULL)
		return(NULL);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "alg") != 0) {
		fclose(f);
		return(NULL);
	}
	if ((s = shaopen(atoi(strtok(NULL, ":\n")))) == NULL) {
		fclose(f);
		return(NULL);
	}
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "H") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	for (i = 0; i < sizeof(s->H)/sizeof(s->H[0]); i++)
		s->H[i] = strtoul(strtok(NULL, ":\n"), NULL, 16);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "block") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	for (i = 0; i < sizeof(s->block); i++)
		s->block[i] = strtoul(strtok(NULL, ":\n"), NULL, 16);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "blockcnt") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	s->blockcnt = strtoul(strtok(NULL, ":\n"), NULL, 10);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "lenhh") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	s->lenhh = strtoul(strtok(NULL, ":\n"), NULL, 10);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "lenhl") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	s->lenhl = strtoul(strtok(NULL, ":\n"), NULL, 10);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "lenlh") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	s->lenlh = strtoul(strtok(NULL, ":\n"), NULL, 10);
	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "lenll") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	s->lenll = strtoul(strtok(NULL, ":\n"), NULL, 10);

#ifdef SHA_384_512

	fgets(line, sizeof(line), f);
	if (strcmp(strtok(line, ":\n"), "HQ") != 0) {
		fclose(f);
		shaclose(s);
		return(NULL);
	}
	/* strtoull() not universal, so cook up an alternative */
	for (i = 0; i < sizeof(s->HQ)/sizeof(s->HQ[0]); i++)
		s->HQ[i] = hex2ull(strtok(NULL, ":\n"));

#endif

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

static SHA *shacomp(alg, bitstr, bitcnt)
int alg;
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;

	if ((s = shaopen(alg)) == NULL)
		return(NULL);
	shawrite(bitstr, bitcnt, s);
	shafinish(s);
	return(s);
}


unsigned char *sha1digest(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static unsigned char digest[SHA1_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((s = shacomp(SHA1, bitstr, bitcnt)) != NULL) {
		memcpy(digest, shadigest(s), sizeof(digest));
		shaclose(s);
	}
	return(digest);
}

char *sha1hex(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char hex[SHA_MAX_HEX_LEN + 1];

	hex[0] = '\0';
	if ((s = shacomp(SHA1, bitstr, bitcnt)) != NULL) {
		strcpy(hex, shahex(s));
		shaclose(s);
	}
	return(hex);
}

char *sha1base64(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char base64[SHA_MAX_BASE64_LEN + 1];

	base64[0] = '\0';
	if ((s = shacomp(SHA1, bitstr, bitcnt)) != NULL) {
		strcpy(base64, shabase64(s));
		shaclose(s);
	}
	return(base64);
}

unsigned char *sha256digest(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static unsigned char digest[SHA256_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((s = shacomp(SHA256, bitstr, bitcnt)) != NULL) {
		memcpy(digest, shadigest(s), sizeof(digest));
		shaclose(s);
	}
	return(digest);
}

char *sha256hex(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char hex[SHA_MAX_HEX_LEN + 1];

	hex[0] = '\0';
	if ((s = shacomp(SHA256, bitstr, bitcnt)) != NULL) {
		strcpy(hex, shahex(s));
		shaclose(s);
	}
	return(hex);
}

char *sha256base64(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char base64[SHA_MAX_BASE64_LEN + 1];

	base64[0] = '\0';
	if ((s = shacomp(SHA256, bitstr, bitcnt)) != NULL) {
		strcpy(base64, shabase64(s));
		shaclose(s);
	}
	return(base64);
}

#ifdef SHA_384_512

unsigned char *sha384digest(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static unsigned char digest[SHA384_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((s = shacomp(SHA384, bitstr, bitcnt)) != NULL) {
		memcpy(digest, shadigest(s), sizeof(digest));
		shaclose(s);
	}
	return(digest);
}

char *sha384hex(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char hex[SHA_MAX_HEX_LEN + 1];

	hex[0] = '\0';
	if ((s = shacomp(SHA384, bitstr, bitcnt)) != NULL) {
		strcpy(hex, shahex(s));
		shaclose(s);
	}
	return(hex);
}

char *sha384base64(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char base64[SHA_MAX_BASE64_LEN + 1];

	base64[0] = '\0';
	if ((s = shacomp(SHA384, bitstr, bitcnt)) != NULL) {
		strcpy(base64, shabase64(s));
		shaclose(s);
	}
	return(base64);
}

unsigned char *sha512digest(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static unsigned char digest[SHA512_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((s = shacomp(SHA512, bitstr, bitcnt)) != NULL) {
		memcpy(digest, shadigest(s), sizeof(digest));
		shaclose(s);
	}
	return(digest);
}

char *sha512hex(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char hex[SHA_MAX_HEX_LEN + 1];

	hex[0] = '\0';
	if ((s = shacomp(SHA512, bitstr, bitcnt)) != NULL) {
		strcpy(hex, shahex(s));
		shaclose(s);
	}
	return(hex);
}

char *sha512base64(bitstr, bitcnt)
unsigned char *bitstr;
unsigned long bitcnt;
{
	SHA *s;
	static char base64[SHA_MAX_BASE64_LEN + 1];

	base64[0] = '\0';
	if ((s = shacomp(SHA512, bitstr, bitcnt)) != NULL) {
		strcpy(base64, shabase64(s));
		shaclose(s);
	}
	return(base64);
}

#endif	/* #ifdef SHA_384_512 */
