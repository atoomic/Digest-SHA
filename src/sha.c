/*
 * sha.c: routines to compute SHA-1/224/256/384/512 digests
 *
 * Ref: NIST FIPS PUB 180-2 Secure Hash Standard
 *
 * Copyright (C) 2003-2004 Mark Shelor, All Rights Reserved
 *
 * Version: 5.00
 * Fri May 14 04:45:00 MST 2004
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sha.h"
#include "sha64bit.h"

#define W32	SHA32			/* useful abbreviations */
#define C32	SHA32_CONST
#define SR32	SHA32_SHR
#define SL32	SHA32_SHL

#define ROTR(x, n)	(SR32(x, n) | SL32(x, 32-(n)))
#define ROTL(x, n)	(SL32(x, n) | SR32(x, 32-(n)))

#define Ch(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define Pa(x, y, z)	((x) ^ (y) ^ (z))
#define Ma(x, y, z)	(((x) & (y)) | ((z) & ((x) | (y))))

#define SIGMA0(x)	(ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x)	(ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x)	(ROTR(x,  7) ^ ROTR(x, 18) ^ SR32(x,  3))
#define sigma1(x)	(ROTR(x, 17) ^ ROTR(x, 19) ^ SR32(x, 10))

#define K1	C32(0x5a827999)		/* SHA-1 constants */
#define K2	C32(0x6ed9eba1)
#define K3	C32(0x8f1bbcdc)
#define K4	C32(0xca62c1d6)

static W32 K256[64] =			/* SHA-224/256 constants */
{
	C32(0x428a2f98), C32(0x71374491), C32(0xb5c0fbcf), C32(0xe9b5dba5),
	C32(0x3956c25b), C32(0x59f111f1), C32(0x923f82a4), C32(0xab1c5ed5),
	C32(0xd807aa98), C32(0x12835b01), C32(0x243185be), C32(0x550c7dc3),
	C32(0x72be5d74), C32(0x80deb1fe), C32(0x9bdc06a7), C32(0xc19bf174),
	C32(0xe49b69c1), C32(0xefbe4786), C32(0x0fc19dc6), C32(0x240ca1cc),
	C32(0x2de92c6f), C32(0x4a7484aa), C32(0x5cb0a9dc), C32(0x76f988da),
	C32(0x983e5152), C32(0xa831c66d), C32(0xb00327c8), C32(0xbf597fc7),
	C32(0xc6e00bf3), C32(0xd5a79147), C32(0x06ca6351), C32(0x14292967),
	C32(0x27b70a85), C32(0x2e1b2138), C32(0x4d2c6dfc), C32(0x53380d13),
	C32(0x650a7354), C32(0x766a0abb), C32(0x81c2c92e), C32(0x92722c85),
	C32(0xa2bfe8a1), C32(0xa81a664b), C32(0xc24b8b70), C32(0xc76c51a3),
	C32(0xd192e819), C32(0xd6990624), C32(0xf40e3585), C32(0x106aa070),
	C32(0x19a4c116), C32(0x1e376c08), C32(0x2748774c), C32(0x34b0bcb5),
	C32(0x391c0cb3), C32(0x4ed8aa4a), C32(0x5b9cca4f), C32(0x682e6ff3),
	C32(0x748f82ee), C32(0x78a5636f), C32(0x84c87814), C32(0x8cc70208),
	C32(0x90befffa), C32(0xa4506ceb), C32(0xbef9a3f7), C32(0xc67178f2)
};

static W32 H01[5] =			/* SHA-1 initial hash value */
{
	C32(0x67452301), C32(0xefcdab89), C32(0x98badcfe),
	C32(0x10325476), C32(0xc3d2e1f0)
};

static W32 H0224[8] =			/* SHA-224 initial hash value */
{
	C32(0xc1059ed8), C32(0x367cd507), C32(0x3070dd17), C32(0xf70e5939),
	C32(0xffc00b31), C32(0x68581511), C32(0x64f98fa7), C32(0xbefa4fa4)
};

static W32 H0256[8] =			/* SHA-256 initial hash value */
{
	C32(0x6a09e667), C32(0xbb67ae85), C32(0x3c6ef372), C32(0xa54ff53a),
	C32(0x510e527f), C32(0x9b05688c), C32(0x1f83d9ab), C32(0x5be0cd19)
};

static void sha1(s, block)		/* SHA-1 transform */
SHA *s;
unsigned char *block;
{
	W32 a, b, c, d, e;
	SHA_STO_CLASS W32 W[16];
	W32 *wp = W;
	W32 *H = s->H;

	SHA32_SCHED(W, block);

/*
 * Use SHA-1 alternate method from FIPS PUB 180-2 (ref. 6.1.3)
 *
 * To improve performance, unroll the loop and consolidate assignments
 * by changing the roles of variables "a" through "e" at each step.
 * Note that the variable "T" is no longer needed.
 */

#define M1(a, b, c, d, e, f, k, w)		\
	e += ROTL(a, 5) + f(b, c, d) + k + w;	\
	b =  ROTL(b, 30)

#define M11(f, k, w)	M1(a, b, c, d, e, f, k, w);
#define M12(f, k, w)	M1(e, a, b, c, d, f, k, w);
#define M13(f, k, w)	M1(d, e, a, b, c, f, k, w);
#define M14(f, k, w)	M1(c, d, e, a, b, f, k, w);
#define M15(f, k, w)	M1(b, c, d, e, a, f, k, w);

#define W11(s)	W[(s+ 0) & 0xf]
#define W12(s)	W[(s+13) & 0xf]
#define W13(s)	W[(s+ 8) & 0xf]
#define W14(s)	W[(s+ 2) & 0xf]

#define A1(s)	(W11(s) = ROTL(W11(s) ^ W12(s) ^ W13(s) ^ W14(s), 1))

	a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];

	M11(Ch, K1,  *wp++); M12(Ch, K1,  *wp++); M13(Ch, K1,  *wp++);
	M14(Ch, K1,  *wp++); M15(Ch, K1,  *wp++); M11(Ch, K1,  *wp++);
	M12(Ch, K1,  *wp++); M13(Ch, K1,  *wp++); M14(Ch, K1,  *wp++);
	M15(Ch, K1,  *wp++); M11(Ch, K1,  *wp++); M12(Ch, K1,  *wp++);
	M13(Ch, K1,  *wp++); M14(Ch, K1,  *wp++); M15(Ch, K1,  *wp++);
	M11(Ch, K1,  *wp  ); M12(Ch, K1, A1( 0)); M13(Ch, K1, A1( 1));
	M14(Ch, K1, A1( 2)); M15(Ch, K1, A1( 3)); M11(Pa, K2, A1( 4));
	M12(Pa, K2, A1( 5)); M13(Pa, K2, A1( 6)); M14(Pa, K2, A1( 7));
	M15(Pa, K2, A1( 8)); M11(Pa, K2, A1( 9)); M12(Pa, K2, A1(10));
	M13(Pa, K2, A1(11)); M14(Pa, K2, A1(12)); M15(Pa, K2, A1(13));
	M11(Pa, K2, A1(14)); M12(Pa, K2, A1(15)); M13(Pa, K2, A1( 0));
	M14(Pa, K2, A1( 1)); M15(Pa, K2, A1( 2)); M11(Pa, K2, A1( 3));
	M12(Pa, K2, A1( 4)); M13(Pa, K2, A1( 5)); M14(Pa, K2, A1( 6));
	M15(Pa, K2, A1( 7)); M11(Ma, K3, A1( 8)); M12(Ma, K3, A1( 9));
	M13(Ma, K3, A1(10)); M14(Ma, K3, A1(11)); M15(Ma, K3, A1(12));
	M11(Ma, K3, A1(13)); M12(Ma, K3, A1(14)); M13(Ma, K3, A1(15));
	M14(Ma, K3, A1( 0)); M15(Ma, K3, A1( 1)); M11(Ma, K3, A1( 2));
	M12(Ma, K3, A1( 3)); M13(Ma, K3, A1( 4)); M14(Ma, K3, A1( 5));
	M15(Ma, K3, A1( 6)); M11(Ma, K3, A1( 7)); M12(Ma, K3, A1( 8));
	M13(Ma, K3, A1( 9)); M14(Ma, K3, A1(10)); M15(Ma, K3, A1(11));
	M11(Pa, K4, A1(12)); M12(Pa, K4, A1(13)); M13(Pa, K4, A1(14));
	M14(Pa, K4, A1(15)); M15(Pa, K4, A1( 0)); M11(Pa, K4, A1( 1));
	M12(Pa, K4, A1( 2)); M13(Pa, K4, A1( 3)); M14(Pa, K4, A1( 4));
	M15(Pa, K4, A1( 5)); M11(Pa, K4, A1( 6)); M12(Pa, K4, A1( 7));
	M13(Pa, K4, A1( 8)); M14(Pa, K4, A1( 9)); M15(Pa, K4, A1(10));
	M11(Pa, K4, A1(11)); M12(Pa, K4, A1(12)); M13(Pa, K4, A1(13));
	M14(Pa, K4, A1(14)); M15(Pa, K4, A1(15));

	H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
}

static void sha256(s, block)		/* SHA-224/256 transform */
SHA *s;
unsigned char *block;
{
	W32 a, b, c, d, e, f, g, h, T1;
	SHA_STO_CLASS W32 W[16];
	W32 *kp = K256;
	W32 *wp = W;
	W32 *H = s->H;

	SHA32_SCHED(W, block);

/*
 * Use same technique as in sha1()
 *
 * To improve performance, unroll the loop and consolidate assignments
 * by changing the roles of variables "a" through "h" at each step.
 * Note that the variable "T2" is no longer needed.
 */

#define M2(a, b, c, d, e, f, g, h, w)				\
	T1 = h  + SIGMA1(e) + Ch(e, f, g) + (*kp++) + w;	\
	h  = T1 + SIGMA0(a) + Ma(a, b, c); d += T1;

#define W21(s)	W[(s+ 0) & 0xf]
#define W22(s)	W[(s+14) & 0xf]
#define W23(s)	W[(s+ 9) & 0xf]
#define W24(s)	W[(s+ 1) & 0xf]

#define A2(s)	(W21(s) += sigma1(W22(s)) + W23(s) + sigma0(W24(s)))

#define M21(w)	M2(a, b, c, d, e, f, g, h, w)
#define M22(w)	M2(h, a, b, c, d, e, f, g, w)
#define M23(w)	M2(g, h, a, b, c, d, e, f, w)
#define M24(w)	M2(f, g, h, a, b, c, d, e, w)
#define M25(w)	M2(e, f, g, h, a, b, c, d, w)
#define M26(w)	M2(d, e, f, g, h, a, b, c, w)
#define M27(w)	M2(c, d, e, f, g, h, a, b, w)
#define M28(w)	M2(b, c, d, e, f, g, h, a, w)

	a = H[0]; b = H[1]; c = H[2]; d = H[3];
	e = H[4]; f = H[5]; g = H[6]; h = H[7];

	M21( *wp++); M22( *wp++); M23( *wp++); M24( *wp++);
	M25( *wp++); M26( *wp++); M27( *wp++); M28( *wp++);
	M21( *wp++); M22( *wp++); M23( *wp++); M24( *wp++);
	M25( *wp++); M26( *wp++); M27( *wp++); M28( *wp  );
	M21(A2( 0)); M22(A2( 1)); M23(A2( 2)); M24(A2( 3));
	M25(A2( 4)); M26(A2( 5)); M27(A2( 6)); M28(A2( 7));
	M21(A2( 8)); M22(A2( 9)); M23(A2(10)); M24(A2(11));
	M25(A2(12)); M26(A2(13)); M27(A2(14)); M28(A2(15));
	M21(A2( 0)); M22(A2( 1)); M23(A2( 2)); M24(A2( 3));
	M25(A2( 4)); M26(A2( 5)); M27(A2( 6)); M28(A2( 7));
	M21(A2( 8)); M22(A2( 9)); M23(A2(10)); M24(A2(11));
	M25(A2(12)); M26(A2(13)); M27(A2(14)); M28(A2(15));
	M21(A2( 0)); M22(A2( 1)); M23(A2( 2)); M24(A2( 3));
	M25(A2( 4)); M26(A2( 5)); M27(A2( 6)); M28(A2( 7));
	M21(A2( 8)); M22(A2( 9)); M23(A2(10)); M24(A2(11));
	M25(A2(12)); M26(A2(13)); M27(A2(14)); M28(A2(15));

	H[0] += a; H[1] += b; H[2] += c; H[3] += d;
	H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

#include "sha64bit.c"

/* w32mem: writes 32-bit word to memory in big-endian order */
static void w32mem(mem, w32)
unsigned char *mem;
W32 w32;
{
	int i;

	for (i = 0; i < 4; i++)
		*mem++ = (unsigned char) (SR32(w32, 24-i*8) & 0xff);
}

#define SETBIT(str, pos)  str[(pos) >> 3] |=  (0x01 << (7 - (pos) % 8))
#define CLRBIT(str, pos)  str[(pos) >> 3] &= ~(0x01 << (7 - (pos) % 8))
#define BYTECNT(bitcnt)   (1 + (((bitcnt) - 1) >> 3))

/* digcpy: writes current state to digest buffer */
static void digcpy(s)
SHA *s;
{
	unsigned int i;

	if (s->blocksize == SHA1_BLOCK_BITS)
		for (i = 0; i < 16; i++)
			w32mem(s->digest + i * 4, s->H[i]);
	else
		digcpy64(s);
}

#define SHA_INIT(alg, transform) 					\
	do {								\
		s->sha = sha ## transform;				\
		memcpy(s->H, H0 ## alg, sizeof(H0 ## alg));		\
		s->blocksize = SHA ## alg ## _BLOCK_BITS;		\
		s->digestlen = SHA ## alg ## _DIGEST_BITS >> 3;		\
	} while (0)

/* sharewind: re-initializes the digest object */
void sharewind(s)
SHA *s;
{
	int alg = s->alg;

	memset(s, 0, sizeof(SHA));
	s->alg = alg;

	if      (alg == SHA1)   SHA_INIT(1, 1);
	else if (alg == SHA224) SHA_INIT(224, 256);
	else if (alg == SHA256) SHA_INIT(256, 256);
	else if (alg == SHA384) SHA_INIT(384, 512);
	else if (alg == SHA512) SHA_INIT(512, 512);
}

/* shaopen: creates a new digest object */
SHA *shaopen(alg)
int alg;
{
	SHA *s;

	SHA_newz(0, s, 1, SHA);
	if (s == NULL)
		return(NULL);
	s->alg = alg;
	if      (alg == SHA1)   SHA_INIT(1, 1);
	else if (alg == SHA224) SHA_INIT(224, 256);
	else if (alg == SHA256) SHA_INIT(256, 256);
	else if (!sha_384_512)  { SHA_free(s); return(NULL); }
	else if (alg == SHA384) SHA_INIT(384, 512);
	else if (alg == SHA512) SHA_INIT(512, 512);
	else                    { SHA_free(s); return(NULL); }
	return(s);
}

/* shadirect: updates state directly (w/o going through s->block) */
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

/* shabytes: updates state for byte-aligned input data */
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

/* shabits: updates state for bit-aligned input data */
static unsigned long shabits(bitstr, bitcnt, s)
unsigned char *bitstr;
unsigned long bitcnt;
SHA *s;
{
	unsigned int i;
	unsigned int gap;
	unsigned long numbits;
	unsigned char buf[1<<9];
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

/* shawrite: triggers a state update using data in bitstr/bitcnt */
unsigned long shawrite(bitstr, bitcnt, s)
unsigned char *bitstr;
unsigned long bitcnt;
SHA *s;
{
	if (bitcnt == 0)
		return(0);
	if (SHA_LO32(s->lenll += bitcnt) < bitcnt)
		if (SHA_LO32(++s->lenlh) == 0)
			if (SHA_LO32(++s->lenhl) == 0)
				s->lenhh++;
	if (s->blockcnt == 0)
		return(shadirect(bitstr, bitcnt, s));
	else if (s->blockcnt % 8 == 0)
		return(shabytes(bitstr, bitcnt, s));
	else
		return(shabits(bitstr, bitcnt, s));
}

/* shafinish: pads remaining block(s) and computes final digest state */
void shafinish(s)
SHA *s;
{
	unsigned int lenpos, lhpos, llpos;

	lenpos = s->blocksize == SHA1_BLOCK_BITS ? 448 : 896;
	lhpos  = s->blocksize == SHA1_BLOCK_BITS ?  56 : 120;
	llpos  = s->blocksize == SHA1_BLOCK_BITS ?  60 : 124;
	SETBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt > lenpos)
		if (s->blockcnt == s->blocksize)
			s->sha(s, s->block), s->blockcnt = 0;
		else
			CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	while (s->blockcnt < lenpos)
		CLRBIT(s->block, s->blockcnt), s->blockcnt++;
	if (s->blocksize != SHA1_BLOCK_BITS) {
		w32mem(s->block + 112, s->lenhh);
		w32mem(s->block + 116, s->lenhl);
	}
	w32mem(s->block + lhpos, s->lenlh);
	w32mem(s->block + llpos, s->lenll);
	s->sha(s, s->block), s->blockcnt = 0;
}

/* shadigest: returns pointer to current digest (binary) */
unsigned char *shadigest(s)
SHA *s;
{
	digcpy(s);
	return(s->digest);
}

#define HEXLEN(bytecnt) ((bytecnt) << 1)

/* shahex: returns pointer to current digest (hexadecimal) */
char *shahex(s)
SHA *s;
{
	int i;

	digcpy(s);
	s->hex[0] = '\0';
	if (HEXLEN(s->digestlen) >= sizeof(s->hex))
		return(s->hex);
	for (i = 0; i < s->digestlen; i++)
		sprintf(s->hex+i*2, "%02x", s->digest[i]);
	return(s->hex);
}

/* map: translation map for Base 64 encoding */
static char map[] =		
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* encbase64: encodes input (0 to 3 bytes) into Base 64 */
static void encbase64(in, n, out)
unsigned char *in;
int n;
char *out;
{
	unsigned char byte[3] = {0, 0, 0};

	out[0] = '\0';
	if (n < 1 || n > 3)
		return;
	memcpy(byte, in, n);
	out[0] = map[byte[0] >> 2];
	out[1] = map[((byte[0] & 0x03) << 4) | (byte[1] >> 4)];
	out[2] = map[((byte[1] & 0x0f) << 2) | (byte[2] >> 6)];
	out[3] = map[byte[2] & 0x3f];
	out[n+1] = '\0';
}

#define B64LEN(bytecnt) (((bytecnt) % 3 == 0) ? ((bytecnt) / 3) * 4 \
	: ((bytecnt) / 3) * 4 + ((bytecnt) % 3) + 1)

/* shabase64: returns pointer to current digest (Base 64) */
char *shabase64(s)
SHA *s;
{
	int n;
	unsigned char *q;
	char out[5];

	digcpy(s);
	s->base64[0] = '\0';
	if (B64LEN(s->digestlen) >= sizeof(s->base64))
		return(s->base64);
	for (n = s->digestlen, q = s->digest; n > 3; n -= 3, q += 3) {
		encbase64(q, 3, out);
		strcat(s->base64, out);
	}
	encbase64(q, n, out);
	strcat(s->base64, out);
	return(s->base64);
}

/* shadsize: returns length of digest in bytes */
int shadsize(s)
SHA *s;
{
	return(s->digestlen);
}

/* shadup: duplicates current digest object */
SHA *shadup(s)
SHA *s;
{
	SHA *p;

	SHA_new(0, p, 1, SHA);
	if (p == NULL)
		return(NULL);
	memcpy(p, s, sizeof(SHA));
	return(p);
}

/* shadump: dumps digest object to a human-readable ASCII file */
int shadump(file, s)
char *file;
SHA *s;
{
	int i;
	SHA_IO *f;
	unsigned char *p;

	if (file == NULL || strlen(file) == 0)
		f = SHA_IO_stdout();
	else if ((f = SHA_IO_open(file, "w")) == NULL)
		return(0);
	SHA_IO_printf(f, "alg:%d\n", s->alg);
	SHA_IO_printf(f, "H");
	p = shadigest(s);
	if (s->alg <= SHA256) for (i = 0; i < 8; i++, p += 4)
		SHA_IO_printf(f, ":%02x%02x%02x%02x",
			p[0], p[1], p[2], p[3]);
	else for (i = 0; i < 8; i++, p += 8)
		SHA_IO_printf(f, ":%02x%02x%02x%02x%02x%02x%02x%02x",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	SHA_IO_printf(f, "\n");
	SHA_IO_printf(f, "block");
	for (i = 0; i < sizeof(s->block); i++)
		SHA_IO_printf(f, ":%02x", s->block[i]);
	SHA_IO_printf(f, "\n");
	SHA_IO_printf(f, "blockcnt:%u\n", s->blockcnt);
	SHA_IO_printf(f, "lenhh:%lu\n", (unsigned long) SHA_LO32(s->lenhh));
	SHA_IO_printf(f, "lenhl:%lu\n", (unsigned long) SHA_LO32(s->lenhl));
	SHA_IO_printf(f, "lenlh:%lu\n", (unsigned long) SHA_LO32(s->lenlh));
	SHA_IO_printf(f, "lenll:%lu\n", (unsigned long) SHA_LO32(s->lenll));
	if (f != SHA_IO_stdout())
		SHA_IO_close(f);
	return(1);
}

/* fgetstr: reads (and returns pointer to) next line of file */
static char *fgetstr(line, maxsize, f)
char *line;
unsigned int maxsize;
SHA_IO *f;
{
	char *p = line;

	if (SHA_IO_eof(f) || maxsize == 0)
		return(NULL);
	for (;; maxsize--) {
		if (SHA_IO_eof(f) || maxsize == 1)
			break;
		if ((*p++ = SHA_IO_getc(f)) == '\n')
			break;
	}
	*p = '\0';
	return(line);
}

/* getval: null-terminates field value, and sets pointer to rest of line */
static char *getval(line, pprest)
char *line;
char **pprest;
{
	char *p;

	for (p = line; *p; p++) {
		if (*p == ':' || *p == '\n') {
			*p++ = '\0';
			*pprest = p;
			return(line);
		}
	}
	return(NULL);
}

/* types of values present in dump file */
#define TYPE_C 1		/* character */
#define TYPE_I 2		/* normal integer */
#define TYPE_32 3		/* 32-bit value */
#define TYPE_64 4		/* 64-bit value */

/* loadvals: checks next line in dump file against tag, and loads values */
static int loadvals(f, tag, type, pval, rep, base)
SHA_IO *f;
char *tag;
int type;
void *pval;
int rep;
int base;
{
	char *p;
	char *pr;
	unsigned char *pc = (unsigned char *) pval;
	unsigned int *pi = (unsigned int *) pval;
	W32 *p32 = (W32 *) pval;
	W64 *p64 = (W64 *) pval;
	char line[1<<9];

	while ((p = fgetstr(line, sizeof(line), f)) != NULL) {
		if (line[0] == '#' || isspace(line[0]))
			continue;
		break;
	}
	if (p == NULL || strcmp(getval(line, &pr), tag) != 0)
		return(0);
	while (rep-- > 0) {
		if ((p = getval(pr, &pr)) == NULL)
			return(0);
		if (type == TYPE_C)
			*pc++ = (unsigned char) strtoul(p, NULL, base);
		else if (type == TYPE_I)
			*pi++ = (unsigned int) strtoul(p, NULL, base);
		else if (type == TYPE_32)
			*p32++ = (W32) strtoul(p, NULL, base);
		else if (type == TYPE_64)
			*p64++ = (W64) strto64(p);
		else
			return(0);
	}
	return(1);
}

/* closeall: closes dump file and de-allocates digest object */
static SHA *closeall(f, s)
SHA_IO *f;
SHA *s;
{
	if (f != NULL && f != SHA_IO_stdin())
		SHA_IO_close(f);
	if (s != NULL)
		shaclose(s);
	return(NULL);
}

/* shaload: creates digest object corresponding to contents of dump file */
SHA *shaload(file)
char *file;
{
	int alg;
	SHA *s;
	SHA_IO *f;

	if (file == NULL || strlen(file) == 0)
		f = SHA_IO_stdin();
	else if ((f = SHA_IO_open(file, "r")) == NULL)
		return(NULL);
	if (!loadvals(f, "alg", TYPE_I, &alg, 1, 10))
		return(closeall(f, NULL));
	if ((s = shaopen(alg)) == NULL)
		return(closeall(f, NULL));
	if (!loadvals(f, "H", alg<=SHA256 ? TYPE_32 : TYPE_64, s->H, 8, 16))
		return(closeall(f, s));
	if (!loadvals(f, "block", TYPE_C, s->block, s->blocksize>>3, 16))
		return(closeall(f, s));
	if (!loadvals(f, "blockcnt", TYPE_I, &s->blockcnt, 1, 10))
		return(closeall(f, s));
	if (!loadvals(f, "lenhh", TYPE_32, &s->lenhh, 1, 10))
		return(closeall(f, s));
	if (!loadvals(f, "lenhl", TYPE_32, &s->lenhl, 1, 10))
		return(closeall(f, s));
	if (!loadvals(f, "lenlh", TYPE_32, &s->lenlh, 1, 10))
		return(closeall(f, s));
	if (!loadvals(f, "lenll", TYPE_32, &s->lenll, 1, 10))
		return(closeall(f, s));
	if (f != SHA_IO_stdin())
		SHA_IO_close(f);
	return(s);
}

/* shaclose: de-allocates digest object */
int shaclose(s)
SHA *s;
{
	if (s != NULL) {
		memset(s, 0, sizeof(SHA));
		SHA_free(s);
	}
	return(0);
}
