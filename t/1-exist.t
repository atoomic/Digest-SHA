use Test::More tests => 2;
BEGIN { 
	use_ok('Digest::SHA', ':all');
	use_ok('Digest::SHA', ':legacy');
};
