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

my $reps = 8000000;
my $bitstr = pack("B*", "11111111" x 127);
my $maxbits = 8 * 127;
my $state = shaopen(1);
my $num;

while ($reps > $maxbits) {
	$num = int(rand($maxbits));
	shawrite($bitstr, $num, $state);
	$reps -= $num;
}
shawrite($bitstr, $reps, $state);
shafinish($state);

is(
	shahex($state),
	"559a512393dd212220ee080730d6f11644ba0222",
	"updates with random bitstring lengths");

shaclose($state);
