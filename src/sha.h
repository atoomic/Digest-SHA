/*
 * sha.h: header file for SHA-1/224/256/384/512 routines
 *
 * Ref: NIST FIPS PUB 180-2 Secure Hash Standard
 *
 * Copyright (C) 2003-2004 Mark Shelor, All Rights Reserved
 *
 * Version: 5.01
 * Fri May 21 13:08:12 MST 2004
 *
 */

#ifndef _INCLUDE_SHA_H_
#define _INCLUDE_SHA_H_

#include <limits.h>

#define SHA32_MAX	4294967295U
#define SHA64_MAX	18446744073709551615U

#define SHA32_SHR(x, n)	((x) >> (n))
#define SHA32_SHL(x, n)	((x) << (n))

#define SHA64_SHR(x, n)	((x) >> (n))
#define SHA64_SHL(x, n)	((x) << (n))

#define SHA32_ALIGNED
#define SHA64_ALIGNED

#define SHA_LO32(x)	(x)

#if USHRT_MAX == SHA32_MAX
	#define SHA32	unsigned short
	#define SHA32_CONST(c)	c ## U
#elif UINT_MAX == SHA32_MAX
	#define SHA32	unsigned int
	#define SHA32_CONST(c)	c ## U
#elif ULONG_MAX == SHA32_MAX
	#define SHA32	unsigned long
	#define SHA32_CONST(c)	c ## UL
#else
	#undef  SHA32_ALIGNED
	#undef  SHA_LO32
	#define SHA_LO32(x)	((x) & SHA32_MAX)
	#undef  SHA32_SHR
	#define SHA32_SHR(x, n)	(SHA_LO32(x) >> (n))
	#define SHA32	unsigned long
	#define SHA32_CONST(c)	c ## UL
#endif

#if defined(ULONG_LONG_MAX) && !defined(ULLONG_MAX)
	#define ULLONG_MAX	ULONG_LONG_MAX
#endif

#if ULONG_MAX > SHA32_MAX && ULONG_MAX == SHA64_MAX
	#define SHA64	unsigned long
	#define SHA64_CONST(c)	c ## UL
#elif defined(ULLONG_MAX) && ULLONG_MAX == SHA64_MAX
	#define SHA64	unsigned long long
	#define SHA64_CONST(c)	c ## ULL
#elif defined(ULLONG_MAX) && ULLONG_MAX != SHA64_MAX
	#undef  SHA64_ALIGNED
	#undef  SHA64_SHR
	#define SHA64_SHR(x, n)	(((x) & SHA64_MAX) >> (n))
	#define SHA64	unsigned long long
	#define SHA64_CONST(c)	c ## ULL
#elif defined(_MSC_VER)
	#define SHA64	unsigned __int64
	#define SHA64_CONST(c)	(SHA64) c
#endif

#if defined(SHA64) && !defined(NO_SHA_384_512)
	#define SHA_384_512
#endif

#if defined(BYTEORDER) && (BYTEORDER == 0x4321 || BYTEORDER == 0x87654321)
	#if defined(SHA32_ALIGNED)
		#define SHA32_SCHED(W, b)	memcpy(W, b, 64)
	#endif
	#if defined(SHA64) && defined(SHA64_ALIGNED)
		#define SHA64_SCHED(W, b)	memcpy(W, b, 128)
	#endif
#endif

#if !defined(SHA32_SCHED)
	#define SHA32_SCHED(W, b) { int t; SHA32 *q = W;		\
		for (t = 0; t < 16; t++, b += 4) *q++ =			\
			(SHA32) b[0] << 24 | (SHA32) b[1] << 16 |	\
			(SHA32) b[2] <<  8 | (SHA32) b[3]; }
#endif

#if defined(SHA64) && !defined(SHA64_SCHED)
	#define SHA64_SCHED(W, b) { int t; SHA64 *q = W;		\
		for (t = 0; t < 16; t++, b += 8) *q++ =			\
			(SHA64) b[0] << 56 | (SHA64) b[1] << 48 |	\
			(SHA64) b[2] << 40 | (SHA64) b[3] << 32 |	\
			(SHA64) b[4] << 24 | (SHA64) b[5] << 16 |	\
			(SHA64) b[6] <<  8 | (SHA64) b[7]; }
#endif

/* SHA_STO_CLASS: static arrays improve transform speed on Intel/Linux */
#if defined(BYTEORDER) && (BYTEORDER == 0x1234 || BYTEORDER == 0x12345678)
	#define SHA_STO_CLASS	static
#else
	#define SHA_STO_CLASS	auto
#endif

/* Override use of static arrays if compiling for thread-safety */
#ifdef SHA_THREAD_SAFE
	#undef  SHA_STO_CLASS
	#define SHA_STO_CLASS	auto
#endif

/* Configure memory management and I/O for Perl or standalone C */
#ifdef SHA_PERL_MODULE
	#define SHA_new			New
	#define SHA_newz		Newz
	#define SHA_free		Safefree
	#define SHA_IO			PerlIO
	#define SHA_IO_stdin()		PerlIO_stdin()
	#define SHA_IO_stdout()		PerlIO_stdout()
	#define SHA_IO_open		PerlIO_open
	#define SHA_IO_close		PerlIO_close
	#define SHA_IO_printf		PerlIO_printf
	#define SHA_IO_eof		PerlIO_eof
	#define SHA_IO_getc		PerlIO_getc
#else
	#define SHA_new(id, p, n, t)	p = (t *) malloc(sizeof(t))
	#define SHA_newz(id, p, n, t)	p = (t *) calloc(n, sizeof(t))
	#define SHA_free		free
	#define SHA_IO			FILE
	#define SHA_IO_stdin()		stdin
	#define SHA_IO_stdout()		stdout
	#define SHA_IO_open		fopen
	#define SHA_IO_close		fclose
	#define SHA_IO_printf		fprintf
	#define SHA_IO_eof		feof
	#define SHA_IO_getc		fgetc
#endif

#define SHA1	1
#define SHA224	224
#define SHA256	256
#define SHA384	384
#define SHA512	512

#define SHA1_BLOCK_BITS		512
#define SHA224_BLOCK_BITS	SHA1_BLOCK_BITS
#define SHA256_BLOCK_BITS	SHA1_BLOCK_BITS
#define SHA384_BLOCK_BITS	1024
#define SHA512_BLOCK_BITS	SHA384_BLOCK_BITS

#define SHA1_DIGEST_BITS	160
#define SHA224_DIGEST_BITS	224
#define SHA256_DIGEST_BITS	256
#define SHA384_DIGEST_BITS	384
#define SHA512_DIGEST_BITS	512

#define SHA_MAX_BLOCK_BITS	SHA512_BLOCK_BITS
#define SHA_MAX_DIGEST_BITS	SHA512_DIGEST_BITS
#define SHA_MAX_HEX_LEN		(SHA_MAX_DIGEST_BITS / 4)
#define SHA_MAX_BASE64_LEN	(1 + (SHA_MAX_DIGEST_BITS / 6))

typedef struct {
	int alg;
	void (*sha)();
	SHA32 H[SHA_MAX_DIGEST_BITS/32];
	unsigned char block[SHA_MAX_BLOCK_BITS/8];
	unsigned int blockcnt;
	unsigned int blocksize;
	SHA32 lenhh, lenhl, lenlh, lenll;
	unsigned char digest[SHA_MAX_DIGEST_BITS/8];
	int digestlen;
	char hex[SHA_MAX_HEX_LEN+1];
	char base64[SHA_MAX_BASE64_LEN+1];
} SHA;

#define SHA_FMT_RAW 1
#define SHA_FMT_HEX 2
#define SHA_FMT_BASE64 3

#if defined(__STDC__) && __STDC__ != 0
	#define _SHA_P(protos)	protos
#else
	#define _SHA_P(protos)	()
#endif

#define _SHA_STATE	SHA *s
#define _SHA_ALG	int alg
#define _SHA_DATA	unsigned char *bitstr, unsigned long bitcnt
#define _SHA_FILE	char *filename

SHA		*shaopen	_SHA_P((_SHA_ALG));
unsigned long	 shawrite	_SHA_P((_SHA_DATA, _SHA_STATE));
void		 shafinish	_SHA_P((_SHA_STATE));
void		 sharewind	_SHA_P((_SHA_STATE));
unsigned char	*shadigest	_SHA_P((_SHA_STATE));
char		*shahex		_SHA_P((_SHA_STATE));
char		*shabase64	_SHA_P((_SHA_STATE));
int		 shadsize	_SHA_P((_SHA_STATE));
SHA		*shadup		_SHA_P((_SHA_STATE));
int		 shadump	_SHA_P((_SHA_FILE, _SHA_STATE));
SHA		*shaload	_SHA_P((_SHA_FILE));
int		 shaclose	_SHA_P((_SHA_STATE));

unsigned char	*sha1digest	_SHA_P((_SHA_DATA));
char		*sha1hex	_SHA_P((_SHA_DATA));
char		*sha1base64	_SHA_P((_SHA_DATA));
unsigned char	*sha224digest	_SHA_P((_SHA_DATA));
char		*sha224hex	_SHA_P((_SHA_DATA));
char		*sha224base64	_SHA_P((_SHA_DATA));
unsigned char	*sha256digest	_SHA_P((_SHA_DATA));
char		*sha256hex	_SHA_P((_SHA_DATA));
char		*sha256base64	_SHA_P((_SHA_DATA));
unsigned char	*sha384digest	_SHA_P((_SHA_DATA));
char		*sha384hex	_SHA_P((_SHA_DATA));
char		*sha384base64	_SHA_P((_SHA_DATA));
unsigned char	*sha512digest	_SHA_P((_SHA_DATA));
char		*sha512hex	_SHA_P((_SHA_DATA));
char		*sha512base64	_SHA_P((_SHA_DATA));

#endif	/* _INCLUDE_SHA_H_ */
