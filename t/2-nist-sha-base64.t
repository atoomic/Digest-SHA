use Test::More qw(no_plan);
use strict;
use integer;
use Digest::SHA qw(sha1_base64 sha224_base64 sha256_base64 sha384_base64 sha512_base64);

# Base64 digests of "abc" for SHA-1/224/256/384/512

my $data = "abc";
my @vecs = (
	\&sha1_base64, "qZk+NkcGgWq6PiVxeFDCbJzQ2J0",
	\&sha224_base64, "Iwl9IjQF2CKGQqR3vaJVsyqtvOS9oLP342ydpw",
	\&sha256_base64, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0",
	\&sha384_base64, "ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn",
	\&sha512_base64, "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw"
);

my $fcn;
my $rsp;

(pop(@vecs) && pop(@vecs)) unless sha512_base64("");
(pop(@vecs) && pop(@vecs)) unless sha384_base64("");

while (@vecs) {
	$fcn = shift(@vecs);
	$rsp = shift(@vecs);
	is(&$fcn($data), $rsp, $rsp);
}
