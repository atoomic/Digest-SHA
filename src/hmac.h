/*
 * hmac.h: header file for HMAC-SHA-1/256/384/512 routines
 *
 * Ref: FIPS PUB 198 The Keyed-Hash Message Authentication Code
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 2.2
 * Sun Nov 16 01:54:00 MST 2003
 *
 */

#ifndef _INCLUDE_HMAC_H_
#define _INCLUDE_HMAC_H_

#include "sha.h"

#define HMAC_KEY_SIZE 64

typedef struct {
	SHA *ksha;
	SHA *isha;
	SHA *osha;
	unsigned char key[HMAC_KEY_SIZE];
} HMAC;

#if defined(__STDC__) && __STDC__ != 0		/* use  prototypes */

HMAC *hmacopen(
	int alg,
	unsigned char *key,
	unsigned int keylen);
unsigned long hmacwrite(
	unsigned char *bitstr,
	unsigned long bitcnt,
	HMAC *h);
void hmacfinish(HMAC *h);
unsigned char *hmacdigest(HMAC *h);
char *hmachex(HMAC *h);
char *hmacbase64(HMAC *h);
int hmacclose(HMAC *h);

unsigned char *hmac1digest(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac1hex(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac1base64(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);

unsigned char *hmac256digest(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac256hex(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac256base64(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);

#ifdef SHA_384_512

unsigned char *hmac384digest(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac384hex(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac384base64(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);

unsigned char *hmac512digest(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac512hex(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);
char *hmac512base64(
	unsigned char *bitstr,
	unsigned long bitcnt,
	unsigned char *key,
	unsigned int keylen);

#endif	/* #ifdef SHA_384_512 */

#else	/* use K&R style declarations */

HMAC *hmacopen();
unsigned long hmacwrite();
void hmacfinish();
unsigned char *hmacdigest();
char *hmachex();
char *hmacbase64();
int hmacclose();

unsigned char *hmac1digest();
char *hmac1hex();
char *hmac1base64();

unsigned char *hmac256digest();
char *hmac256hex();
char *hmac256base64();

#ifdef SHA_384_512

unsigned char *hmac384digest();
char *hmac384hex();
char *hmac384base64();

unsigned char *hmac512digest();
char *hmac512hex();
char *hmac512base64();

#endif	/* #ifdef SHA_384_512 */

#endif	/* use K&R style declarations */

#endif	/* _INCLUDE_HMAC_H_ */
