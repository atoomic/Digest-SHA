use Test::More tests => 1;
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
