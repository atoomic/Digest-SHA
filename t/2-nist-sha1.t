use Test::More tests => 3;
use strict;
use integer;
use Digest::SHA qw(sha1hex);

my @vecs = (
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"a" x 1000000
);

my @sha1rsp = (
	"a9993e364706816aba3e25717850c26c9cd0d89d",
	"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
	"34aa973cd4c4daa4f61eeb2bdbad27316534016f"
);

my @name = (
	"SHA-1(abc)",
	"SHA-1(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
	"SHA-1('a' x 1000000)",
);

for (my $i = 0; $i < @vecs; $i++) {
	is(
		sha1hex($vecs[$i], length($vecs[$i]) * 8),
		$sha1rsp[$i],
		$name[$i]
	);
}
