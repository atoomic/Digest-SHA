use Test::More tests => 1;
use Digest::SHA qw(sha1);
use strict;
use integer;

my @vecs = (
	"hello world"
);

my @rsp = (
	pack("H*", "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
);

my @name = (
	"hello world"
);

for (my $i = 0; $i < @vecs; $i++) {
	is(
		sha1($vecs[$i]),
		$rsp[$i],
		$name[$i]
	);
}
