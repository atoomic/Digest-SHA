use Test::More tests => 1;
use strict;
use integer;
use Digest::SHA;

my $reps = 8000000;
my $bitstr = pack("B*", "11111111" x 127);
my $maxbits = 8 * 127;
my $state = Digest::SHA->new(1);
my $num;

while ($reps > $maxbits) {
	$num = int(rand($maxbits));
	$state->add_bits($bitstr, $num);
	$reps -= $num;
}
$state->add_bits($bitstr, $reps);

is(
	$state->hexdigest,
	"559a512393dd212220ee080730d6f11644ba0222",
	"updates with random bitstring lengths");
