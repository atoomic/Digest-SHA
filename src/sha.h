/*
 * sha.h: header file for SHA-1/256/384/512 routines
 *
 * Ref: NIST FIPS PUB 180-2 Secure Hash Standard
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 2.1
 * Sun Nov  9 03:39:01 MST 2003
 *
 */

#ifndef _INCLUDE_SHA_H_
#define _INCLUDE_SHA_H_

#include <limits.h>


#if defined(ULONG_LONG_MAX) && !defined(NO_SHA_384_512)
	#define SHA_384_512
#endif


#define SHA1	1
#define SHA256	256
#define SHA384	384
#define SHA512	512

#define SHA1_BLOCK_BITS		512
#define SHA256_BLOCK_BITS	SHA1_BLOCK_BITS
#define SHA384_BLOCK_BITS	1024
#define SHA512_BLOCK_BITS	SHA384_BLOCK_BITS

#define SHA1_DIGEST_BITS	160
#define SHA256_DIGEST_BITS	256
#define SHA384_DIGEST_BITS	384
#define SHA512_DIGEST_BITS	512

#define SHA_MAX_BLOCK_BITS	SHA512_BLOCK_BITS
#define SHA_MAX_DIGEST_BITS	SHA512_DIGEST_BITS
#define SHA_MAX_HEX_LEN		(SHA_MAX_DIGEST_BITS / 4)
#define SHA_MAX_BASE64_LEN	(1 + (SHA_MAX_DIGEST_BITS / 6))

#define SHA_FMT_RAW 1
#define SHA_FMT_HEX 2
#define SHA_FMT_BASE64 3

typedef struct {
	int alg;
	void (*sha)();
	unsigned long H[SHA256_DIGEST_BITS/32];
	unsigned char block[SHA_MAX_BLOCK_BITS/8];
	unsigned int blockcnt;
	unsigned int blocksize;
	unsigned long lenhh, lenhl, lenlh, lenll;
	unsigned char digest[SHA_MAX_DIGEST_BITS/8];
	int digestlen;
	char hex[SHA_MAX_HEX_LEN+1];
	char base64[SHA_MAX_BASE64_LEN+1];

#ifdef SHA_384_512
	unsigned long long HQ[SHA_MAX_DIGEST_BITS/64];
#endif

} SHA;


#if defined(__STDC__) && __STDC__ != 0		/* use  prototypes */

SHA *shaopen(int alg);
unsigned long shawrite(
	unsigned char *bitstr,
	unsigned long bitcnt,
	SHA *s);
void shafinish(SHA *s);
unsigned char *shadigest(SHA *s);
char *shahex(SHA *s);
char *shabase64(SHA *s);
SHA *shadup(SHA *s);
int shadump(char *file, SHA *s);
SHA *shaload(char *file);
int shaclose(SHA *s);

unsigned char *sha1digest(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha1hex(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha1base64(
	unsigned char *bitstr,
	unsigned long bitcnt);

unsigned char *sha256digest(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha256hex(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha256base64(
	unsigned char *bitstr,
	unsigned long bitcnt);

#ifdef SHA_384_512

unsigned char *sha384digest(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha384hex(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha384base64(
	unsigned char *bitstr,
	unsigned long bitcnt);

unsigned char *sha512digest(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha512hex(
	unsigned char *bitstr,
	unsigned long bitcnt);
char *sha512base64(
	unsigned char *bitstr,
	unsigned long bitcnt);

#endif	/* #ifdef SHA_384_512 */

#else	/* use K&R style declarations */

SHA *shaopen();
unsigned long shawrite();
void shafinish();
unsigned char *shadigest();
char *shahex();
char *shabase64();
SHA *shadup();
int shadump();
SHA *shaload();
int shaclose();

unsigned char *sha1digest();
char *sha1hex();
char *sha1base64();

unsigned char *sha256digest();
char *sha256hex();
char *sha256base64();

#ifdef SHA_384_512

unsigned char *sha384digest();
char *sha384hex();
char *sha384base64();

unsigned char *sha512digest();
char *sha512hex();
char *sha512base64();

#endif	/* #ifdef SHA_384_512 */

#endif	/* use K&R style declarations */

#endif	/* _INCLUDE_SHA_H_ */
