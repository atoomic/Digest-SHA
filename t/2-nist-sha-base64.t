use Test::More qw(no_plan);
use strict;
use integer;
use Digest::SHA qw(sha1base64 sha256base64 sha384base64 sha512base64);

# Base64 digests of "abc" for SHA-1/256/384/512

my @vecs = (
	"qZk+NkcGgWq6PiVxeFDCbJzQ2J0",
	"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0",
	"ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn",
	"3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw"
);

my $rsp;

eval { sha512base64("") };
pop(@vecs) if $@;

eval { sha384base64("") };
pop(@vecs) if $@;

for (my $i = 0; $i < @vecs; $i++) {
	if ($i == 0) {
		$rsp = sha1base64("abc");
	}
	elsif ($i == 1) {
		$rsp = sha256base64("abc");
	}
	elsif ($i == 2) {
		$rsp = sha384base64("abc");
	}
	elsif ($i == 3) {
		$rsp = sha512base64("abc");
	}
	else {
		$rsp = "Too many vectors";
	}
	is(
		$rsp,
		$vecs[$i],
		$rsp
	);
}
