# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 10;

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

use strict;
use integer;

use Digest::SHA qw(sha1base64);

my @vecs = (
	'T(byfo0]^!,7a`',	184649,	"bEImGz/6nki2zjRWQm+JhRCa8jk",
	'][H}C7*d',		917208,	"yvyYHbxuBkxaGHup8+hq8TdNPNA",
	'fny+_P3CKx5',		629781,	"Xny9s6/f8mqajMBIGjDANBoA6ks",
	's\c,?F>D&xk%',		305384,	"mFpEvfJKonSgHhUg8cnQTIbi1YA",
	'/$z\jjWt',		467637,	"x+0zhmPQf53j3vvaFuJiUxkl5N4",
	'*oU$&2\y',		828068,	"NEBBvlKDjRJqI2x1jxHCVfh/Suk",
	'(/gERl?@p[',		382652,	"pXTOz6hHuCCCTRrn+cRSWYvy6r0",
	'_@]K-7BY',		341602,	"R3ZeANHC73fKKodSN6mFI9wQk80",
	'JtOP)-KvNS(',		239394,	"372OYvGoP4uT4jKsXc2yQZJTh0U",
	'Z%8yus@vT`V"llC',	416883,	"qKSHYy2ymGaNgX8CNquA/uwxCTk",
);

my $str;

for (my $i = 0; $i < @vecs/3; $i++) {
	$str = $vecs[$i*3] x $vecs[$i*3+1];
	is(
		sha1base64($str, length($str) * 8),
		$vecs[$i*3+2],
		"$vecs[$i*3] x $vecs[$i*3+1] = " . $vecs[$i*3+2]);
}
