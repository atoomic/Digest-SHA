use Test::More tests => 3;
use strict;
use integer;
use Digest::SHA qw(sha224_hex);

my @vecs = (
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"a" x 1000000
);

my @sha224rsp = (
	"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
	"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
	"20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
);

my @name = (
	"SHA-224(abc)",
	"SHA-224(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
	"SHA-224('a' x 1000000)",
);

for (my $i = 0; $i < @vecs; $i++) {
	is(
		sha224_hex($vecs[$i]),
		$sha224rsp[$i],
		$name[$i]
	);
}
