/*
 * hmac.c: routines to compute HMAC-SHA-1/256/384/512 digests
 *
 * Ref: FIPS PUB 198 The Keyed-Hash Message Authentication Code
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 4.0.0
 * Sat Nov 29 23:18:45 MST 2003
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hmac.h"
#include "sha.h"
#include "fmt.h"

HMAC *hmacopen(alg, key, keylen)
int alg;
unsigned char *key;
unsigned int keylen;
{
	int i;
	HMAC *h;

	if ((h = (HMAC *) calloc(1, sizeof(HMAC))) == NULL)
		return(NULL);
	if ((h->isha = shaopen(alg)) == NULL) {
		free(h);
		return(NULL);
	}
	if ((h->osha = shaopen(alg)) == NULL) {
		shaclose(h->isha);
		free(h);
		return(NULL);
	}
	if (keylen <= sizeof(h->key))
		memcpy(h->key, key, keylen);
	else {
		if ((h->ksha = shaopen(alg)) == NULL) {
			shaclose(h->isha);
			shaclose(h->osha);
			free(h);
			return(NULL);
		}
		shawrite(key, keylen * 8, h->ksha);
		shafinish(h->ksha);
		memcpy(h->key, shadigest(h->ksha), h->ksha->digestlen);
		shaclose(h->ksha);
	}
	for (i = 0; i < 64; i++)
		h->key[i] ^= 0x5c;
	shawrite(h->key, 512, h->osha);
	for (i = 0; i < 64; i++)
		h->key[i] ^= (0x5c ^ 0x36);
	shawrite(h->key, 512, h->isha);
	memset(h->key, 0, sizeof(h->key));
	return(h);
}

unsigned long hmacwrite(bitstr, bitcnt, h)
unsigned char *bitstr;
unsigned long bitcnt;
HMAC *h;
{
	return(shawrite(bitstr, bitcnt, h->isha));
}

void hmacfinish(h)
HMAC *h;
{
	shafinish(h->isha);
	shawrite(shadigest(h->isha), h->isha->digestlen * 8, h->osha);
	shaclose(h->isha);
	shafinish(h->osha);
}

unsigned char *hmacdigest(h)
HMAC *h;
{
	return(shadigest(h->osha));
}

char *hmachex(h)
HMAC *h;
{
	return(shahex(h->osha));
}

char *hmacbase64(h)
HMAC *h;
{
	return(shabase64(h->osha));
}

int hmacclose(h)
HMAC *h;
{
	shaclose(h->osha);
	if (h != NULL) {
		memset(h, 0, sizeof(HMAC));
		free(h);
	}
	return(0);
}

static unsigned char *hmaccomp(alg, fmt, bitstr, bitcnt, key, keylen)
int alg;
int fmt;
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static unsigned char digest[SHA_MAX_HEX_LEN+1];
	unsigned char *ret = digest;

	if ((h = hmacopen(alg, key, keylen)) == NULL)
		return(NULL);
	hmacwrite(bitstr, bitcnt, h);
	hmacfinish(h);
	if (fmt == SHA_FMT_RAW)
		memcpy(digest, hmacdigest(h), h->osha->digestlen); 
	else if (fmt == SHA_FMT_HEX)
		strcpy((char *) digest, hmachex(h)); 
	else if (fmt == SHA_FMT_BASE64)
		strcpy((char *) digest, hmacbase64(h)); 
	else
		ret = NULL;
	hmacclose(h);
	return(ret);
}

#define HMAC_DIRECT(type, name, alg, fmt) 			\
type name(bitstr, bitcnt, key, keylen)				\
unsigned char *bitstr;						\
unsigned long bitcnt;						\
unsigned char *key;						\
unsigned int keylen;						\
{								\
	return((type) hmaccomp(alg, fmt, bitstr, bitcnt,	\
					key, keylen));		\
}

HMAC_DIRECT(unsigned char *, hmac1digest, SHA1, SHA_FMT_RAW)
HMAC_DIRECT(char *, hmac1hex, SHA1, SHA_FMT_HEX)
HMAC_DIRECT(char *, hmac1base64, SHA1, SHA_FMT_BASE64)

HMAC_DIRECT(unsigned char *, hmac256digest, SHA256, SHA_FMT_RAW)
HMAC_DIRECT(char *, hmac256hex, SHA256, SHA_FMT_HEX)
HMAC_DIRECT(char *, hmac256base64, SHA256, SHA_FMT_BASE64)

HMAC_DIRECT(unsigned char *, hmac384digest, SHA384, SHA_FMT_RAW)
HMAC_DIRECT(char *, hmac384hex, SHA384, SHA_FMT_HEX)
HMAC_DIRECT(char *, hmac384base64, SHA384, SHA_FMT_BASE64)

HMAC_DIRECT(unsigned char *, hmac512digest, SHA512, SHA_FMT_RAW)
HMAC_DIRECT(char *, hmac512hex, SHA512, SHA_FMT_HEX)
HMAC_DIRECT(char *, hmac512base64, SHA512, SHA_FMT_BASE64)
