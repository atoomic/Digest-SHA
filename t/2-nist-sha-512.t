use Test::More qw(no_plan);
use strict;
use integer;
use Digest::SHA qw(sha512_hex);

my @vecs = (
	"abc",
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	"a" x 1000000
);

my @sha512rsp = (
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
	"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
);

my @name = (
	"SHA-512(abc)",
	"SHA-512(abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijk...)",
	"SHA-512('a' x 1000000)",
);

my $skip = sha512_hex("") ? 0 : 1;

for (my $i = 0; $i < @vecs; $i++) {
	SKIP: {
		skip("64-bit operations not supported", 1) if $skip;
		is(
			sha512_hex($vecs[$i]),
			$sha512rsp[$i],
			$name[$i]
		);
	}
}
