/*
 * hmac.c: routines to compute HMAC-SHA-1/256/384/512 digests
 *
 * Ref: FIPS PUB 198 The Keyed-Hash Message Authentication Code
 *
 * Copyright (C) 2003 Mark Shelor, All Rights Reserved
 *
 * Version: 2.0
 * Sat Nov  1 02:03:19 MST 2003
 *
 */

#include <stdio.h>
#include <string.h>
#include "hmac.h"
#include "sha.h"

HMAC *hmacopen(alg, key, keylen)
int alg;
unsigned char *key;
unsigned int keylen;
{
	int i;
	HMAC *h;

	if ((h = (HMAC *) malloc(sizeof(HMAC))) == NULL)
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
	memset(h->key, 0, sizeof(h->key));
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
	memset(h, 0, sizeof(HMAC));
	free(h);
	return(0);
}

static HMAC *hmaccomp(alg, bitstr, bitcnt, key, keylen)
int alg;
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;

	if ((h = hmacopen(alg, key, keylen)) == NULL)
		return(NULL);
	hmacwrite(bitstr, bitcnt, h);
	hmacfinish(h);
	return(h);
}

unsigned char *hmac1digest(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static unsigned char digest[SHA1_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((h = hmaccomp(SHA1, bitstr, bitcnt, key, keylen)) != NULL) {
		memcpy(digest, hmacdigest(h), sizeof(digest));
		hmacclose(h);
	}
	return(digest);
}

char *hmac1hex(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char hex[SHA_MAX_HEX_LEN+1];

	hex[0] = '\0';
	if ((h = hmaccomp(SHA1, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(hex, hmachex(h));
		hmacclose(h);
	}
	return(hex);
}

char *hmac1base64(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char base64[SHA_MAX_BASE64_LEN+1];

	base64[0] = '\0';
	if ((h = hmaccomp(SHA1, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(base64, hmacbase64(h));
		hmacclose(h);
	}
	return(base64);
}

unsigned char *hmac256digest(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static unsigned char digest[SHA256_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((h = hmaccomp(SHA256, bitstr, bitcnt, key, keylen)) != NULL) {
		memcpy(digest, hmacdigest(h), sizeof(digest));
		hmacclose(h);
	}
	return(digest);
}

char *hmac256hex(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char hex[SHA_MAX_HEX_LEN+1];

	hex[0] = '\0';
	if ((h = hmaccomp(SHA256, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(hex, hmachex(h));
		hmacclose(h);
	}
	return(hex);
}

char *hmac256base64(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char base64[SHA_MAX_BASE64_LEN+1];

	base64[0] = '\0';
	if ((h = hmaccomp(SHA256, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(base64, hmacbase64(h));
		hmacclose(h);
	}
	return(base64);
}

#ifdef SHA_384_512

unsigned char *hmac384digest(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static unsigned char digest[SHA384_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((h = hmaccomp(SHA384, bitstr, bitcnt, key, keylen)) != NULL) {
		memcpy(digest, hmacdigest(h), sizeof(digest));
		hmacclose(h);
	}
	return(digest);
}

char *hmac384hex(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char hex[SHA_MAX_HEX_LEN+1];

	hex[0] = '\0';
	if ((h = hmaccomp(SHA384, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(hex, hmachex(h));
		hmacclose(h);
	}
	return(hex);
}

char *hmac384base64(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char base64[SHA_MAX_BASE64_LEN+1];

	base64[0] = '\0';
	if ((h = hmaccomp(SHA384, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(base64, hmacbase64(h));
		hmacclose(h);
	}
	return(base64);
}

unsigned char *hmac512digest(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static unsigned char digest[SHA512_DIGEST_BITS/8];

	memset(digest, 0, sizeof(digest));
	if ((h = hmaccomp(SHA512, bitstr, bitcnt, key, keylen)) != NULL) {
		memcpy(digest, hmacdigest(h), sizeof(digest));
		hmacclose(h);
	}
	return(digest);
}

char *hmac512hex(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char hex[SHA_MAX_HEX_LEN+1];

	hex[0] = '\0';
	if ((h = hmaccomp(SHA512, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(hex, hmachex(h));
		hmacclose(h);
	}
	return(hex);
}

char *hmac512base64(bitstr, bitcnt, key, keylen)
unsigned char *bitstr;
unsigned long bitcnt;
unsigned char *key;
unsigned int keylen;
{
	HMAC *h;
	static char base64[SHA_MAX_BASE64_LEN+1];

	base64[0] = '\0';
	if ((h = hmaccomp(SHA512, bitstr, bitcnt, key, keylen)) != NULL) {
		strcpy(base64, hmacbase64(h));
		hmacclose(h);
	}
	return(base64);
}

#endif	/* #ifdef SHA_384_512 */
