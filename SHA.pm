package Digest::SHA;

use 5.008;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Digest::SHA ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.

our %EXPORT_TAGS = ( 'all' => [ qw(
	hmac1base64
	hmac1hex
	hmac256base64
	hmac256hex
	hmac384base64
	hmac384hex
	hmac512base64
	hmac512hex
	sha1base64
	sha1hex
	sha256base64
	sha256hex
	sha384base64
	sha384hex
	sha512base64
	sha512hex
	shabase64
	shaclose
	shadump
	shadup
	shafinish
	shahex
	shaload
	shaopen
	shawrite
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw();

our $VERSION = '2.4';

require XSLoader;
XSLoader::load('Digest::SHA', $VERSION);

# Preloaded methods go here.

sub shawrite {
	my($data, $len, $state) = @_;

	if (!defined($state)) {
		$state = $len;
		$len = 8 * length($data);
	}
	return(c_shawrite($data, $len, $state));
}

sub sha1hex {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha1hex($data, $len));
}

sub sha256hex {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha256hex($data, $len));
}

sub sha384hex {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha384hex($data, $len));
}

sub sha512hex {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha512hex($data, $len));
}

sub sha1base64 {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha1base64($data, $len));
}

sub sha256base64 {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha256base64($data, $len));
}

sub sha384base64 {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha384base64($data, $len));
}

sub sha512base64 {
	my($data, $len) = @_;

	$len = 8 * length($data) unless defined($len);
	return(c_sha512base64($data, $len));
}

sub hmac1hex {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac1hex($data, $dlen, $key, $klen));
}

sub hmac256hex {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac256hex($data, $dlen, $key, $klen));
}

sub hmac384hex {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac384hex($data, $dlen, $key, $klen));
}

sub hmac512hex {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac512hex($data, $dlen, $key, $klen));
}

sub hmac1base64 {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac1base64($data, $dlen, $key, $klen));
}

sub hmac256base64 {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac256base64($data, $dlen, $key, $klen));
}

sub hmac384base64 {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac384base64($data, $dlen, $key, $klen));
}

sub hmac512base64 {
	my($data, $dlen, $key, $klen) = @_;

	if (!defined($key)) {
		$key = $dlen;
		$dlen = 8 * length($data);
		$klen = length($key);
	}
	elsif (!defined($klen)) {
		$klen = length($key);
	}
	return(c_hmac512base64($data, $dlen, $key, $klen));
}

sub shadump {
	my($file, $state) = @_;

	if (!defined($state)) {
		$state = $file;
		$file = "";
	}
	return(c_shadump($file, $state));
}

sub shaload {
	my($file) = @_;

	if (!defined($file)) {
		$file = "";
	}
	return(c_shaload($file));
}

1;
__END__

=head1 NAME

Digest::SHA - Perl extension for SHA-1/256/384/512 and HMAC-SHA

=head1 SYNOPSIS

  # Direct computation
  use Digest::SHA qw(sha1hex sha1base64 sha256hex sha256base64 ... );

  $digest = sha1hex($data);			# byte-oriented data
  $digest = sha1hex($data, $data_len_in_bits);	# bit-oriented

  $digest = sha384base64($data);
  $digest = sha512base64($data, $data_len_in_bits);
  ...

  # Iterative computation
  use Digest::SHA qw(shaopen shawrite shafinish shaclose
			shahex shabase64 shadup shadump shaload);

  $state = shaopen($alg);	# $alg = 1, 256, 384, or 512

  shawrite($data, [ $data_len_in_bits, ] $state);
  shawrite($moredata, [ $moredata_len_in_bits, ] $state);

  shafinish($state);

  $digest = shahex($state);
  $digest = shabase64($state);

  shaclose($state);

  # HMAC-SHA keyed hash
  use Digest::SHA qw(hmac1hex hmac1base64 hmac256hex ... );

  $digest = hmac1hex($data, [ $data_len_in_bits, ] $key);
  $digest = hmac1base64($data, [ $data_len_in_bits, ] $key);
  ...

=head1 ABSTRACT

Digest::SHA provides a Perl interface to all algorithms defined in
the NIST Secure Hash Standard (FIPS PUB 180-2).  The module also
includes support for computing keyed SHA hashes using the HMAC
algorithm described in FIPS PUB 198.  The routines are general-purpose,
allowing digests to be calculated for bit-strings as well as
byte-strings.  The underlying code is written in C.

=head1 DESCRIPTION

Digest::SHA endeavors to provide a complete and portable implementation
of the NIST Secure Hash Standard.  It differs from the majority of
existing SHA packages which usually omit support for bit-string
inputs, and often don't include the entire range of transforms
specified by NIST.

The module attempts to be as fast and efficient as possible, with
the goal of combining Perl's ease-of-use with C's performance
advantages.  For added convenience, the package includes the Perl
script I<shasum> to perform myriad SHA operations through the
command line.  Just go to the I<utils/> directory and type I<perl
shasum --help> for details.

Digest::SHA offers two ways to calculate digests: all-at-once, or
in stages.  The first is simpler, and often requires only one line
of Perl.  The second is more general, allowing input to be processed
in chunks.

To illustrate the difference, the following program calculates the
SHA-256 digest of I<hello world> using the two different methods:

	use Digest::SHA ':all';

	my $data = "hello world";
	my @frags = split(//, $data);

	my $method1 = sha256hex($data);

	my $state = shaopen(256);
	for (@frags) {
		shawrite($_, $state);
	}
	shafinish($state);
	my $method2 = shahex($state);

	print $method1 eq $method2 ?
		"whew!\n" : "career in aluminum siding\n";

B<PLEASE NOTE>: the optional I<$data_len_in_bits> argument of
I<sha256hex()> and I<shawrite()> is omitted in the above example
since the input data is byte-oriented.

Computing the digest value of a bit-string is also easy.  Let's
say the input string is 446 bits, consisting of the fragment I<110>
repeated 148 times, followed by the fragment I<11>.  Here's how to
calculate its SHA-1 digest:

	$digest = sha1hex(pack("B*", ("110"x148)."11"), 446);

When calculating keyed-hashes using the HMAC-SHA functions, it's
important to note that the optional data length argument is in
B<bits>.  If omitted, the corresponding data is assumed to be
byte-oriented.

So, to compute the HMAC-SHA-1 digest of I<burpleson> using a suitable
key, the code would go something like this:

	$data = "burpleson";
	$key = "poe";
	$digest = hmac1hex($data, $key);

or, if you're paid by the character:

	$digest = hmac1hex($data, 8 * length($data), $key);

=head1 EXPORT

None by default.

=head1 EXPORTABLE FUNCTIONS

=over 4

Provided your C compiler supports 64-bit types (i.e. long long),
all of these functions will be available for use.  If it doesn't,
you won't be able to perform SHA-384 and SHA-512 transforms, both
of which require 64-bit operations.

=item I<Direct Functions>

=item B<sha1hex($data [ , $data_len_in_bits ] )>

Returns the SHA-1 digest of I<$data>, encoded as a 40-character
hexadecimal string.

=item B<sha1base64($data [ , $data_len_in_bits ] )>

Returns the SHA-1 digest of I<$data>, encoded as a Base64 string.

=item B<sha256hex($data [ , $data_len_in_bits ] )>

Returns the SHA-256 digest of I<$data>, encoded as a 64-character
hexadecimal string.

=item B<sha256base64($data [ , $data_len_in_bits ] )>

Returns the SHA-256 digest of I<$data>, encoded as a Base64 string.

=item B<sha384hex($data [ , $data_len_in_bits ] )>

Returns the SHA-384 digest of I<$data>, encoded as a 96-character
hexadecimal string.  This function will return a null value if your
C compiler lacks support for 64-bit integral types.

=item B<sha384base64($data [ , $data_len_in_bits ] )>

Returns the SHA-384 digest of I<$data>, encoded as a Base64 string.
This function will return a null value if your C compiler lacks
support for 64-bit integral types.

=item B<sha512hex($data [ , $data_len_in_bits ] )>

Returns the SHA-512 digest of I<$data>, encoded as a 128-character
hexadecimal string.  This function will return a null value if your
C compiler lacks support for 64-bit integral types.

=item B<sha512base64($data [ , $data_len_in_bits ] )>

Returns the SHA-512 digest of I<$data>, encoded as a Base64 string.
This function will return a null value if your C compiler lacks
support for 64-bit integral types.

=item I<Iterative Functions>

=item B<shaopen($alg)>

Begins the iterative calculation of a SHA digest, returning a state
variable for use by subsequent iterative I<sha...()> functions.
The $alg argument determines which SHA transform will be used (e.g.
$alg = 256 corresponds to SHA-256).  This function will return a
null value for $alg = 384 or $alg = 512 if your C compiler lacks
support for 64-bit integral types.

=item B<shawrite($data, [ $data_len_in_bits, ] $state)>

Updates the SHA state by feeding in I<$data>.  The caller invokes
this function repeatedly until all data has been processed.  The
value of I<$data_len_in_bits> B<must not> exceed 2^32-1 for each
individual call of I<shawrite()>.  However, per the NIST standard,
the total accumulated length of the data stream may be as large as
2^64-1 for SHA-1 and SHA-256, or 2^128-1 for SHA-384 and SHA-512.

=item B<shafinish($state)>

Finalizes the SHA calculation by padding and transforming the final
block(s), and updating the state.  It is necessary to call this
function before attempting to access the final digest value through
I<shahex()> or I<shabase64()>.  However, calling them beforehand
may be useful to folks who are interested in examining SHA's internal
state at various stages of the digest computation.

=item B<shahex($state)>

Returns the digest value, encoded as a hexadecimal string.

=item B<shabase64($state)>

Returns the digest value, encoded as a Base64 string.

=item B<shadup($state)>

Returns a duplicate copy of the current state.

=item B<shadump( [ $filename, ] $state)>

Provides persistent storage of intermediate SHA states by writing
the contents of the I<$state> structure to disk.  If I<$filename>
is missing, or equal to the empty string, the state information
will be written to stdout.  In combination with I<shaload()> and
I<shadup()>, this routine can help to speed up SHA calculations
for data sets that share identical headers.  See the I<gillogly-hard>
script in the I<t/> subdirectory for a simple illustration.

=item B<shaload( [ $filename ] )>

Retrieves the contents of an intermediate SHA state that was
previously stored to disk by I<shadump()>.  If I<$filename> is
missing, or equal to the empty string, the state information will
be read from stdin.  The I<shaload()> routine returns a fresh copy
of this state, so it's not necessary to create or initialize it
beforehand by calling I<shaopen()>.

=item B<shaclose($state)>

Frees all memory allocated during the previous I<shaopen()>,
I<shadup()>, or I<shaload()> call.

=item I<HMAC-SHA Functions>

=item B<hmac1hex($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-1 digest of I<$data/$key>, encoded as a
40-character hexadecimal string.

=item B<hmac1base64($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-1 digest of I<$data/$key>, encoded as a Base64
string.

=item B<hmac256hex($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-256 digest of I<$data/$key>, encoded as a
64-character hexadecimal string.

=item B<hmac256base64($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-256 digest of I<$data/$key>, encoded as a
Base64 string.

=item B<hmac384hex($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-384 digest of I<$data/$key>, encoded as a
96-character hexadecimal string.  This function will return a null
value if your C compiler lacks support for 64-bit integral types.

=item B<hmac384base64($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-384 digest of I<$data/$key>, encoded as a
Base64 string.  This function will return a null value if your C
compiler lacks support for 64-bit integral types.

=item B<hmac512hex($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-512 digest of I<$data/$key>, encoded as a
128-character hexadecimal string.  This function will return a null
value if your C compiler lacks support for 64-bit integral types.

=item B<hmac512base64($data, [ $data_len_in_bits, ] $key)>

Returns the HMAC-SHA-512 digest of I<$data/$key>, encoded as a
Base64 string.  This function will return a null value if your C
compiler lacks support for 64-bit integral types.

=back

=head1 SEE ALSO

L<Digest::SHA1>

The Secure Hash Standard (FIPS PUB 180-2) can be found at:

http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

The Keyed-Hash Message Authentication Code (HMAC):

http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf

=head1 AUTHOR

Mark Shelor, E<lt>mshelor@comcast.netE<gt>

The author extends special thanks to Jeffrey Friedl and Chris
Skiscim for their valuable comments and suggestions.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003 by Mark Shelor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
