#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#define shadump c_shadump
#define shaload c_shaload

#include <src/sha.c>
#include <src/hmac.c>


MODULE = Digest::SHA		PACKAGE = Digest::SHA		

PROTOTYPES: ENABLE

#include <src/sha.h>
#include <src/hmac.h>

char *
hmac1hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac1base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac256hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac256base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac384hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac384base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac512hex(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
hmac512base64(bitstr, bitcnt, key, keylen)
	unsigned char *	bitstr
	unsigned long	bitcnt
	unsigned char *	key
	unsigned int	keylen

char *
sha1base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha1hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha256base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha256hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha384base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha384hex(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha512base64(bitstr, bitcnt)
	unsigned char *	bitstr
	unsigned long	bitcnt

char *
sha512hex(bitstr, bitcnt)
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
shawrite(bitstr, bitcnt, s)
	unsigned char *	bitstr
	unsigned long	bitcnt
	SHA *	s

void
add(self, ...)
        AV* self
PREINIT:
        STRLEN len;
        unsigned char *data;
        unsigned int i;
        SHA *state;
PPCODE:
        state = (SHA *) (SvIV(SvRV(*av_fetch(self, 0, 0))));
        for (i = 1; i < items; i++) {
                data = (unsigned char *)(SvPV(ST(i), len));
                shawrite(data, len << 3, state);
        }
        XSRETURN(1);
