# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 1;

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

use strict;
use integer;

use Digest::SHA qw(sha1hex);

my @vecs = (
	"hello world"
);

my @rsp = (
	"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
);

my @name = (
	"hello world"
);

for (my $i = 0; $i < @vecs; $i++) {
	is(
		sha1hex($vecs[$i], length($vecs[$i]) * 8),
		$rsp[$i],
		$name[$i]
	);
}
