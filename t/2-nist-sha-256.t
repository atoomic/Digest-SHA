use Test::More tests => 3;
use strict;
use integer;
use Digest::SHA qw(sha256hex);

my @vecs = (
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"a" x 1000000
);

my @sha256rsp = (
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
);

my @name = (
	"SHA-256(abc)",
	"SHA-256(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
	"SHA-256('a' x 1000000)",
);

for (my $i = 0; $i < @vecs; $i++) {
	is(
		sha256hex($vecs[$i]),
		$sha256rsp[$i],
		$name[$i]
	);
}
