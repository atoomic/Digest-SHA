use Test::More tests => 2;
use strict;
use integer;
use Digest::SHA qw(new clone reset add addfile hexdigest b64digest);

# Test all OO methods using first two SHA-256 vectors from FIPS PUB 180-2

open(FILE, ">ootest$$.txt");
binmode(FILE);
print FILE "bcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
close(FILE);

my @vecs = (
	"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0",
	"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
);

my $ctx = Digest::SHA->new();
$ctx->reset(256);
$ctx->add("a");

my $rsp = shift(@vecs);
is($ctx->clone->add("b", "c")->b64digest, $rsp, $rsp);

$rsp = shift(@vecs);
open(FILE, "ootest$$.txt");
binmode(FILE);
is($ctx->addfile(*FILE)->hexdigest, $rsp, $rsp);

unlink("ootest$$.txt");
