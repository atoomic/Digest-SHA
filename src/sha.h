/*
 * sha.h: header file for SHA-1/224/256/384/512 routines
 *
 * Ref: NIST FIPS PUB 180-2 Secure Hash Standard
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 4.2.0
 * Sat Dec 27 16:08:00 MST 2003
 *
 */

#ifndef _INCLUDE_SHA_H_
#define _INCLUDE_SHA_H_

#include <limits.h>

#if defined(ULONG_LONG_MAX) && !defined(NO_SHA_384_512)
	#define SHA_384_512
#endif

#ifdef SHA_BIG_ENDIAN
	#define sha_big_endian 1
#else
	#define sha_big_endian 0
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
	unsigned long H[SHA_MAX_DIGEST_BITS/32];
	unsigned char block[SHA_MAX_BLOCK_BITS/8];
	unsigned int blockcnt;
	unsigned int blocksize;
	unsigned long lenhh, lenhl, lenlh, lenll;
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
