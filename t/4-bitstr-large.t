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

use Digest::SHA qw(shaopen shawrite shafinish shahex shaclose);

my $i;
my $bitstr = pack("B*", "11111111" x 10000);
my $state = shaopen(1);

shawrite($bitstr, 1, $state);
for ($i = 0; $i < 99; $i++) {
	shawrite($bitstr, 80000, $state);
}
shawrite($bitstr, 79999, $state);
shafinish($state);

is(
	shahex($state),
	"559a512393dd212220ee080730d6f11644ba0222",
	"updates with large bitstrings on non-byte-aligned boundaries");

shaclose($state);
