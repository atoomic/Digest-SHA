package Digest::SHA;

use strict;
use warnings;
use integer;

our $VERSION = '4.1.0';

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT_OK = qw(
	hmac_sha1	hmac_sha1_base64	hmac_sha1_hex
	hmac_sha256	hmac_sha256_base64	hmac_sha256_hex
	hmac_sha384	hmac_sha384_base64	hmac_sha384_hex
	hmac_sha512	hmac_sha512_base64	hmac_sha512_hex
	sha1		sha1_base64		sha1_hex
	sha256		sha256_base64		sha256_hex
	sha384		sha384_base64		sha384_hex
	sha512		sha512_base64		sha512_hex);

# If possible, inherit from Digest::base (which depends on MIME::Base64)

eval {
	require MIME::Base64;
	require Digest::base;
	push(@ISA, 'Digest::base');
};
if ($@) {
	*addfile = \&Addfile;
	*hexdigest = \&Hexdigest;
	*b64digest = \&B64digest;
}

require XSLoader;
XSLoader::load('Digest::SHA', $VERSION);

# Preloaded methods go here.

# The following routines aren't time-critical, so they can be left in Perl

sub new {
	my($class, $alg) = @_;
	$alg =~ s/\D+//g if defined $alg;
	if (ref($class)) {	# instance method
		unless (defined($alg) && ($alg != $class->algorithm)) {
			sharewind($class->[0]);
			return($class);
		}
		shaclose($class->[0]) if $class->[0];
		$class->[0] = shaopen($alg) || return;
		return($class);
	}
	$alg = 1 unless defined $alg;
	my $self = [];
	$self->[0] = shaopen($alg) || return;
	bless($self, $class);
	return($self);
}

sub DESTROY {
	my $self = shift;
	shaclose($self->[0]) if $self->[0];
}

sub clone {
	my $self = shift;
	my $copy = [];
	$copy->[0] = shadup($self->[0]) || return;
	bless($copy, ref($self));
	return($copy);
}

*reset = \&new;

sub add_bits {
	my($self, $data, $nbits) = @_;
	unless (defined $nbits) {
		$nbits = length($data);
		$data = pack("B*", $data);
	}
	shawrite($data, $nbits, $self->[0]);
	return($self);
}

# local copy of "addfile" in case Digest::base not installed

sub Addfile {	# this is "addfile" from Digest::base 1.00
    my ($self, $handle) = @_;

    my $n;
    my $buf = "";

    while (($n = read($handle, $buf, 4096))) {
	$self->add($buf);
    }
    unless (defined $n) {
	require Carp;
	Carp::croak("Read failed: $!");
    }

    $self;
}

sub dump {
	my $self = shift;
	my $file = shift || "";

	shadump($file, $self->[0]) || return;
	return($self);
}

sub load {
	my $class = shift;
	my $file = shift || "";
	if (ref($class)) {	# instance method
		shaclose($class->[0]) if $class->[0];
		$class->[0] = shaload($file) || return;
		return($class);
	}
	my $self = [];
	$self->[0] = shaload($file) || return;
	bless($self, $class);
	return($self);
}

1;
__END__

=head1 NAME

Digest::SHA - Perl extension for SHA-1/256/384/512

=head1 SYNOPSIS (SHA)

 # Functional style
 use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha256 sha256_hex ... );

 $digest = sha1($data);
 $digest = sha1_hex($data);
 $digest = sha1_base64($data);


 # OO style
 use Digest::SHA;

 $sha = Digest::SHA->new($alg);		# alg = 1, 256, 384, 512

 $sha->add($data);
 $sha->addfile(*FILE);

 $digest = $sha->digest;
 $digest = $sha->hexdigest;
 $digest = $sha->b64digest;

=head1 SYNOPSIS (HMAC-SHA)

 # Functional style only
 use Digest::SHA qw(hmac_sha1 hmac_sha1_hex hmac_sha1_base64 ... );

 $digest = hmac_sha1($data, $key);
 $digest = hmac_sha1_hex($data, $key);
 $digest = hmac_sha1_base64($data, $key);

 $digest = hmac_sha256($data, $key);
 $digest = hmac_sha256_hex($data, $key);
 $digest = hmac_sha256_base64($data, $key);

=head1 ABSTRACT

Digest::SHA is a full implementation of the NIST Secure Hash
Standard.  It gives Perl programmers a convenient way to calculate
SHA-1, SHA-256, SHA-384, and SHA-512 message digests.  The module
can handle all types of input, including partial-byte data.

=head1 DESCRIPTION

Digest::SHA is a Perl interface to portable C code that implements
all four hashing algorithms defined in NIST FIPS PUB 180-2.  It
offers two ways to calculate digests: all-at-once, or in stages.

To illustrate, the following short program computes the SHA-256
digest of "hello world" using each approach:

	use Digest::SHA qw(sha256_hex);

	$data = "hello world";
	@frags = split(//, $data);

	# all-at-once (Functional style)
	$digest1 = sha256_hex($data);

	# in-stages (OO style)
	$state = Digest::SHA->new(256);
	for (@frags) { $state->add($_) }
	$digest2 = $state->hexdigest;

	print $digest1 eq $digest2 ?
		"whew!\n" : "career in aluminum siding\n";

To calculate the digest of an n-bit message where I<n> is not a
multiple of 8, use the I<add_bits()> method.  For example, consider
the 446-bit message consisting of the bit-string "110" repeated
148 times, followed by "11".  Here's how to calculate its SHA-1
digest:

	$bits = "110" x 148 . "11";
	$digest = Digest::SHA->new(1)->add_bits($bits)->hexdigest;

Note that for larger bit-strings, it's more efficient to use the
two-argument version I<add_bits($data, $nbits)>, where I<$data> is
in the customary packed binary format used for Perl strings.

The module also lets you save intermediate SHA states to disk, or
display them on standard output.  The I<dump()> method generates
a portable, human-readable text-file describing the current state
of computation.  You can subsequently retrieve the file with
I<load()> to resume where the calculation left off.

If you're curious about what a state description looks like, just
run the following:

	Digest::SHA->new(256)->add("COL Bat Guano" x 1964)->dump;

As an added convenience, the Digest::SHA module offers routines to
calculate keyed hashes using the HMAC-SHA-1/256/384/512 algorithms.
These services exist in functional form only, and mimic the style
and behavior of the I<sha()>, I<sha_hex()>, and I<sha_base64()>
functions.

	# test vector from draft-ietf-ipsec-ciph-sha-256-01.txt

	print hmac_sha256_hex("Hi There", chr(0x0b) x 32), "\n";

=head1 EXPORT

None by default.

=head1 EXPORTABLE FUNCTIONS

=over 4

Provided your C compiler supports the "long long" type, all of
these functions will be available for use.  Otherwise, you won't
be able to perform the SHA-384 and SHA-512 transforms, both of
which require portable 64-bit operations.

=back

I<Functional style>

=over 4

=item B<sha1($data, ...)>

=item B<sha256($data, ...)>

=item B<sha384($data, ...)>

=item B<sha512($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA-1/256/384/512 digest encoded as a binary string.

=item B<sha1_hex($data, ...)>

=item B<sha256_hex($data, ...)>

=item B<sha384_hex($data, ...)>

=item B<sha512_hex($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA-1/256/384/512 digest encoded as a hexadecimal string.

=item B<sha1_base64($data, ...)>

=item B<sha256_base64($data, ...)>

=item B<sha384_base64($data, ...)>

=item B<sha512_base64($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA-1/256/384/512 digest encoded as a Base64 string.

=back

I<OO style>

=over 4

=item B<$sha = Digest::SHA-E<gt>new($alg)>

Returns a new Digest::SHA object.  Values for I<$alg> are 1, 256,
384, or 512.  It's also possible to use common string representations
of the algorithm (e.g. "sha256", "SHA-384").  If the argument is
missing, SHA-1 will be used by default.

Invoking I<new> as an instance method will not create a new object;
instead, it will simply reset the object to the initial state
associated with I<$alg>.  If the argument is missing, the object
will continue using the same algorithm that was selected at creation.

=item B<$sha-E<gt>reset($alg)>

This method has exactly the same effect as I<$sha-E<gt>new($alg)>.
In fact, I<reset> is just an alias for I<new>.

=item B<$sha-E<gt>hashsize>

Returns the number of digest bits for this object.  The values are
160, 256, 384, and 512 for SHA-1, SHA-256, SHA-384, and SHA-512,
respectively.

=item B<$sha-E<gt>algorithm>

Returns the digest algorithm for this object.  The values are 1,
256, 384, and 512 for SHA-1, SHA-256, SHA-384, and SHA-512,
respectively.

=item B<$sha-E<gt>clone>

Returns a duplicate copy of the I<$sha> object.

=item B<$sha-E<gt>add($data, ...)>

Logically joins the arguments into a single string, and uses that
string to update the current I<$sha> digest state.  In other words,
the following statements have the same effect:

	$sha->add("a"); $sha->add("b"); $sha->add("c");
	$sha->add("a")->add("b")->add("c");
	$sha->add("a", "b", "c");
	$sha->add("abc");

The return value is the updated object itself.

=item B<$sha-E<gt>add_bits($data, $nbits)>

=item B<$sha-E<gt>add_bits($bits)>

Updates the current digest state by appending bits to it.  The
return value is the updated object itself.

The first form causes the most-significant I<$nbits> of I<$data>
to be appended to the stream.  The I<$data> argument is in the
customary binary format used for Perl strings.

The second form takes an ASCII string of "0" and "1" characters as
its argument.  It's equivalent to

	$sha->add_bits(pack("B*", $bits), length($bits));

So, the following two statements do the same thing:

	$ctx->add_bits("111100001010");
	$ctx->add_bits("\xF0\xA0", 12);

=item B<$sha-E<gt>addfile(*FILE)>

Reads from I<FILE> until EOF, and appends that data to the current
state.  The return value is the updated I<$sha> object itself.

This method is inherited if L<Digest::base> is installed on your
system.  Otherwise, a functionally equivalent substitute is used.

=item B<$sha-E<gt>dump($filename)>

Provides persistent storage of intermediate SHA states by writing
a portable, human-readable representation of the current state to
I<$filename>.  If the argument is missing, or equal to the empty
string, the state information will be written to STDOUT.

=item B<$sha-E<gt>load($filename)>

Returns a Digest::SHA object representing the intermediate SHA
state that was previously stored to I<$filename>.  If called as a
class method, a new object is created; if called as an instance
method, the object is reset to the state contained in I<$filename>.
If the argument is missing, or equal to the empty string, the state
information will be read from STDIN.

=item B<$sha-E<gt>digest>

Returns the digest encoded as a binary string.

Note that the I<digest> method is a read-once operation. Once it
has been performed, the Digest::SHA object is automatically reset
in preparation for calculating another digest value.  Call
I<$sha-E<gt>clone-E<gt>digest> if it's necessary to preserve the
original digest state.

=item B<$sha-E<gt>hexdigest>

Returns the digest encoded as a hexadecimal string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>hexdigest> if it's necessary to preserve
the original digest state.

This method is inherited if L<Digest::base> is installed on your
system.  Otherwise, a functionally equivalent substitute is used.

=item B<$sha-E<gt>b64digest>

Returns the digest encoded as a Base64 string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>b64digest> if it's necessary to preserve
the original digest state.

This method is inherited if L<Digest::base> is installed on your
system.  Otherwise, a functionally equivalent substitute is used.

=back

I<HMAC-SHA-1/256/384/512>

=over 4

=item B<hmac_sha1($data, $key)>

=item B<hmac_sha256($data, $key)>

=item B<hmac_sha384($data, $key)>

=item B<hmac_sha512($data, $key)>

Returns the HMAC-SHA-1/256/384/512 digest of I<$data>/I<$key>, with
the result encoded as a binary string.  Multiple I<$data> arguments
are allowed, provided that I<$key> is the last argument in the
list.

=item B<hmac_sha1_hex($data, $key)>

=item B<hmac_sha256_hex($data, $key)>

=item B<hmac_sha384_hex($data, $key)>

=item B<hmac_sha512_hex($data, $key)>

Returns the HMAC-SHA-1/256/384/512 digest of I<$data>/I<$key>, with
the result encoded as a hexadecimal string.  Multiple I<$data>
arguments are allowed, provided that I<$key> is the last argument
in the list.

=item B<hmac_sha1_base64($data, $key)>

=item B<hmac_sha256_base64($data, $key)>

=item B<hmac_sha384_base64($data, $key)>

=item B<hmac_sha512_base64($data, $key)>

Returns the HMAC-SHA-1/256/384/512 digest of I<$data>/I<$key>, with
the result encoded as a Base64 string.  Multiple I<$data> arguments
are allowed, provided that I<$key> is the last argument in the
list.

=back

=head1 SEE ALSO

L<Digest>, L<Digest::SHA1>, L<Digest::SHA2>

The Secure Hash Standard (FIPS PUB 180-2) can be found at:

http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

The Keyed-Hash Message Authentication Code (HMAC):

http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf

=head1 AUTHOR

Mark Shelor, E<lt>mshelor@comcast.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003 by Mark Shelor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

L<perlartistic>

=cut
