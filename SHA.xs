#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#define shawrite c_shawrite

#define hmac1hex c_hmac1hex
#define hmac256hex c_hmac256hex
#define hmac384hex c_hmac384hex
#define hmac512hex c_hmac512hex

#define hmac1base64 c_hmac1base64
#define hmac256base64 c_hmac256base64
#define hmac384base64 c_hmac384base64
#define hmac512base64 c_hmac512base64

#define sha1hex c_sha1hex
#define sha256hex c_sha256hex
#define sha384hex c_sha384hex
#define sha512hex c_sha512hex

#define sha1base64 c_sha1base64
#define sha256base64 c_sha256base64
#define sha384base64 c_sha384base64
#define sha512base64 c_sha512base64

#define shadump c_shadump
#define shaload c_shaload

#include <src/sha.c>
#include <src/hmac.c>


MODULE = Digest::SHA		PACKAGE = Digest::SHA		

PROTOTYPES: ENABLE

#include <src/sha.h>
#include <src/hmac.h>

char *
c_hmac1hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac1base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac256hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac256base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac384hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac384base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac512hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_hmac512base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
c_sha1base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha1hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha256base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha256hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha384base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha384hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha512base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
c_sha512hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
shabase64(s)
	SHA *	s

int
shaclose(s)
	SHA *	s

int
c_shadump(file, s)
	char *	file
	SHA *	s

SHA *
shadup(s)
	SHA *	s

void
shafinish(s)
	SHA *	s

char *
shahex(s)
	SHA *	s

SHA *
c_shaload(file)
	char *	file

SHA *
shaopen(alg)
	int	alg

unsigned long
c_shawrite(bitstr, bitcnt, s)
	unsigned char *	bitstr
	unsigned long	bitcnt
	SHA *	s

