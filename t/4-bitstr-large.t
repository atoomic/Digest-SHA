use Test::More tests => 1;
use strict;
use integer;
use Digest::SHA;

my $i;
my $bitstr = pack("B*", "11111111" x 10000);
my $state = Digest::SHA->new("1");

$state->add_bits($bitstr, 1);	# creates an alignment nuisance
for ($i = 0; $i < 99; $i++) {
	$state->add_bits($bitstr, 80000);
}
$state->add_bits($bitstr, 79999);

is(
	$state->hexdigest,
	"559a512393dd212220ee080730d6f11644ba0222",
	"updates with large bitstrings on non-byte-aligned boundaries");
