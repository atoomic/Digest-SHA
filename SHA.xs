#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <src/sha.c>


MODULE = Digest::SHA		PACKAGE = Digest::SHA		

#include <src/sha.h>

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

#ifdef SHA_384_512

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

#endif

char *
shabase64(s)
	SHA *	s

int
shaclose(s)
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
shaopen(alg)
	int	alg

unsigned long
shawrite(bitstr, bitcnt, s)
	unsigned char *	bitstr
	unsigned long	bitcnt
	SHA *	s
