use Test::More tests => 1;
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
