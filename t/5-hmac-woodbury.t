# HMAC-SHA-1/256/384/512 test vectors
#	ref. cpan bug #7181, Adam Woodbury (awoodbury@mitre.org)

use Test;
use strict;
use integer;
use Digest::SHA qw(
	hmac_sha1_hex
	hmac_sha256_hex
	hmac_sha384_hex
	hmac_sha512_hex
);

BEGIN { plan tests => 4 }

my $data = "abc";
my $key  = "Test";

my @rsp = (
	"5a3295d6b47441bec1de3c0a74dfefc5a5002c74",
	"db5f1d85a1669f93baa1202b0a0f2b9acfb160a4027e23cef32b35a1bf5d4b5e",
	"14aa1152e0e14ee172ab8a31b1fd4d6924087e8eecb2ebf52e588593605f8ee47c8a40f50f18c853bff18b690f211111",
	"4abf9dc8e6ac4b44ded6eba7a221262cd07cdc82553173a23678966e4d2290bcf0dc3922da524c85bdc774c5ddef8dfbd24c99429b3065b13f91a166af27630a"
);

my $skip = hmac_sha384_hex("", "") ? 0 : 1;

ok(hmac_sha1_hex($data, $key), $rsp[0]);
ok(hmac_sha256_hex($data, $key), $rsp[1]);

skip($skip, hmac_sha384_hex($data, $key), $rsp[2]);
skip($skip, hmac_sha512_hex($data, $key), $rsp[3]);
