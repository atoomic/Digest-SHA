# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

######################### initialize test data ######################### 

use strict;
use integer;

use File::Basename qw(dirname);

# extract bit messages

my $i;
my @msgs;
my @hashes;
my @cnts;
my $bitstr;
my $bitval;
my $line;

my $datafile;

BEGIN {
	$datafile = dirname($0) . "/nist/byte-messages.sha1";
	open(F, $datafile);
	while (<F>) {
		last if (/Type 3/);
		$_ = substr($_, 0, length($_) - 2);
		next unless (/^[0-9^ ]/);
		$line .= $_;
		if (/\^$/) {
			$line = substr($line, 0, length($line) - 1);
			@cnts = split(' ', $line);
			$bitstr = "";
			$bitval = $cnts[1];
			for ($i = 0; $i < $cnts[0]; $i++) {
				$bitstr .= $bitval x $cnts[$i+2];
				$bitval = $bitval eq "1" ? "0" : "1";
			}
			push(@msgs, $bitstr);
			$line = "";
		}
	}
	close(F);

	$datafile = dirname($0) . "/nist/byte-hashes.sha1";
	open(F, $datafile);
	while (<F>) {
		$_ = substr($_, 0, length($_) - 2);
		next unless (/^[0-9A-F]/);
		if (/\^$/) {
			$_ = substr($_, 0, length($_) - 2);
			push(@hashes, $_);
		}
	}
	close(F);
}

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => scalar(@msgs);

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.


use Digest::SHA qw(sha1hex);

for (my $i = 0; $i < @msgs; $i++) {
	is(
		uc(sha1hex(pack("B*", $msgs[$i]), length($msgs[$i]))),
		$hashes[$i],
		$hashes[$i]
	);
}
