use Test::More tests => 1;
use strict;
use integer;
use Digest::SHA qw(shaopen shawrite shafinish shahex shaclose);

my $i;
my $bitstr = pack("B*", "1" x 3999);
my $state = shaopen(1);

# Note that (1 + 2 + ... + 3999) + 2000 = 8000000

for ($i = 0; $i <= 3999; $i++) {
	shawrite($bitstr, $i, $state);
}
shawrite($bitstr, 2000, $state);
shafinish($state);

is(
	shahex($state),
	"559a512393dd212220ee080730d6f11644ba0222",
	"updates with increasing bitstring lengths 0..3999"
);

shaclose($state);
