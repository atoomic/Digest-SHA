package Digest::SHA;

#use 5.008;
use base 'Digest::base';
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
'all' => [ qw(
	hmac_sha1
	hmac_sha1_base64
	hmac_sha1_hex
	hmac_sha256
	hmac_sha256_base64
	hmac_sha256_hex
	hmac_sha384
	hmac_sha384_base64
	hmac_sha384_hex
	hmac_sha512
	hmac_sha512_base64
	hmac_sha512_hex
	sha1
	sha1_base64
	sha1_hex
	sha256
	sha256_base64
	sha256_hex
	sha384
	sha384_base64
	sha384_hex
	sha512
	sha512_base64
	sha512_hex) ],
'legacy' => [ qw(
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
	shawrite) ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} }, @{ $EXPORT_TAGS{'legacy'} } );

our @EXPORT = qw();

our $VERSION = '4.0.2';

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

sub sha1 { return(pack("H*", sha1hex(join("", @_)))) }
sub sha1_hex { return(sha1hex(join("", @_))) }
sub sha1_base64 { return(sha1base64(join("", @_))) }

sub sha256 { return(pack("H*", sha256hex(join("", @_)))) }
sub sha256_hex { return(sha256hex(join("", @_))) }
sub sha256_base64 { return(sha256base64(join("", @_))) }

sub sha384 { return(pack("H*", sha384hex(join("", @_)))) }
sub sha384_hex { return(sha384hex(join("", @_))) }
sub sha384_base64 { return(sha384base64(join("", @_))) }

sub sha512 { return(pack("H*", sha512hex(join("", @_)))) }
sub sha512_hex { return(sha512hex(join("", @_))) }
sub sha512_base64 { return(sha512base64(join("", @_))) }

sub hmac_sha1 {
	my $key = pop;
	return(pack("H*", hmac1hex(join("", @_), $key)))
}

sub hmac_sha1_hex {
	my $key = pop;
	return(hmac1hex(join("", @_), $key));
}

sub hmac_sha1_base64 {
	my $key = pop;
	return(hmac1base64(join("", @_), $key));
}

sub hmac_sha256 {
	my $key = pop;
	return(pack("H*", hmac256hex(join("", @_), $key)))
}

sub hmac_sha256_hex {
	my $key = pop;
	return(hmac256hex(join("", @_), $key));
}

sub hmac_sha256_base64 {
	my $key = pop;
	return(hmac256base64(join("", @_), $key));
}

sub hmac_sha384 {
	my $key = pop;
	return(pack("H*", hmac384hex(join("", @_), $key)))
}

sub hmac_sha384_hex {
	my $key = pop;
	return(hmac384hex(join("", @_), $key));
}

sub hmac_sha384_base64 {
	my $key = pop;
	return(hmac384base64(join("", @_), $key));
}

sub hmac_sha512 {
	my $key = pop;
	return(pack("H*", hmac512hex(join("", @_), $key)))
}

sub hmac_sha512_hex {
	my $key = pop;
	return(hmac512hex(join("", @_), $key));
}

sub hmac_sha512_base64 {
	my $key = pop;
	return(hmac512base64(join("", @_), $key));
}

sub new {
	my $class = shift;
	if (ref($class)) {	# instance method
		shaclose($class->{STATE}) if $class->{STATE};
		$class->{ALG} = shift || $class->{ALG};
		$class->{ALG} =~ s/\D+//g;
		$class->{STATE} = shaopen($class->{ALG}) || return;
		return($class);
	}
	my $self = {};
	$self->{ALG} = shift || 1;
	$self->{ALG} =~ s/\D+//g;
	$self->{STATE} = shaopen($self->{ALG}) || return;
	bless($self, $class);
	return($self);
}

sub DESTROY {
	my $self = shift;
	shaclose($self->{STATE}) if $self->{STATE};
}

sub hashsize {
	my $self = shift;
	return(length(shahex($self->{STATE})) * 4);
}

sub clone {
	my $self = shift;
	my $copy = Digest::SHA->new($self->{ALG});
	shaclose($copy->{STATE}) if $copy->{STATE};
	$copy->{STATE} = shadup($self->{STATE});
	return($copy);
}

*reset = \&new;

sub add {
	my $self = shift;
	my $data = join("", @_);
	shawrite($data, $self->{STATE});
	return($self);
}

sub add_bits {
	my($self, $data, $nbits) = @_;
	unless (defined $nbits) {
		$nbits = length($data);
		$data = pack("B*", $data);
	}
	shawrite($data, $nbits, $self->{STATE});
	return($self);
}

# tweaked by jcd
sub addfile {
	return Digest::base::addfile(@_);
}

sub dump {
	my $self = shift;
	my $file = shift || "";

	c_shadump($file, $self->{STATE}) || return;
	return($self);
}

sub load {
	my $class = shift;
	my $file = shift || "";
	if (ref($class)) {	# instance method
		shaclose($class->{STATE}) if $class->{STATE};
		return unless $class->{STATE} = c_shaload($file);
		$class->{ALG} = $class->hashsize();
		$class->{ALG} = 1 if $class->{ALG} == 160;
		return($class);
	}
	my $self = {};
	return unless $self->{STATE} = c_shaload($file);
	bless($self, $class);
	$self->{ALG} = $self->hashsize();
	$self->{ALG} = 1 if $self->{ALG} == 160;
	return($self);
}

sub digest {
	my $self = shift;
	shafinish($self->{STATE});
	my $val = pack("H*", shahex($self->{STATE}));
	$self->reset;
	return($val);
}

sub hexdigest {
	my $self = shift;
	shafinish($self->{STATE});
	my $val = shahex($self->{STATE});
	$self->reset;
	return($val);
}

sub b64digest {
	my $self = shift;
	shafinish($self->{STATE});
	my $val = shabase64($self->{STATE});
	$self->reset;
	return($val);
}

1;
__END__

=head1 NAME

Digest::SHA - Perl extension for SHA-1/256/384/512

=head1 SYNOPSIS

 # Functional style
 use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha256 sha256_hex ... );

 $digest = sha1($data);
 $digest = sha1_hex($data);
 $digest = sha1_base64($data);


 # OO style
 use Digest::SHA;

 $sha = Digest::SHA->new($alg);		# alg = 1, 256, 384, 512

 $sha->add($data);
 $sha->add_bits($data, $nbits);
 $sha->add_bits($bits);
 $sha->addfile(*FILE);

 $digest = $sha->digest;
 $digest = $sha->hexdigest;
 $digest = $sha->b64digest;

=head1 ABSTRACT

Digest::SHA implements all four algorithms of the NIST Secure Hash
Standard: SHA-1, SHA-256, SHA-384, and SHA-512.  The module is
capable of calculating digest values of bit-wise as well as byte-wise
messages.

=head1 DESCRIPTION

Digest::SHA provides a complete and portable implementation of the
NIST Secure Hash Standard.  It offers two different ways to calculate
digests: all-at-once, or in stages.  The following program calculates
the SHA-256 digest of "hello world" using each method:

	use Digest::SHA ':all';

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

To compute the digest of an n-bit message where I<n> is not a
multiple of 8, use the I<add_bits()> method.  As an example, consider
the 446-bit message consisting of the fragment "110" repeated 148
times, followed by the fragment "11".  Here's how to calculate its
SHA-1 digest:

	$bits = "110" x 148 . "11";
	$digest = Digest::SHA->new(1)->add_bits($bits)->hexdigest;

Note that for larger bit-strings, it's more efficient to use the
two-argument version I<add_bits($data, $nbits)>, where I<$data> is
in the customary packed binary format used for Perl strings.

As a temporary convenience, the Digest::SHA module provides
self-contained routines to calculate HMAC-SHA-1/256/384/512 digests.
These services exist in functional form only, and closely mimic
the style and behavior of the I<shaX>, I<shaX_hex>, and I<shaX_base64>
functions.  It's expected that they will be moved to an appropriate
Digest::HMAC module as soon as the corresponding OO implementation
is developed and tested.

=head1 EXPORT

None by default.

=head1 EXPORTABLE FUNCTIONS

=over 4

Provided your C compiler supports the "long long" type, all of
these functions will be available for use.  If it doesn't, you
won't be able to perform the SHA-384 and SHA-512 transforms, both
of which require portable 64-bit operations.

=back

I<Functional style>

=over 4

=item B<sha1($data, ...)>

=item B<sha256($data, ...)>

=item B<sha384($data, ...)>

=item B<sha512($data, ...)>

Joins the arguments into a single string, and returns its
SHA-1/256/384/512 digest encoded as a binary string.

=item B<sha1_hex($data, ...)>

=item B<sha256_hex($data, ...)>

=item B<sha384_hex($data, ...)>

=item B<sha512_hex($data, ...)>

Joins the arguments into a single string, and returns its
SHA-1/256/384/512 digest encoded as a hexadecimal string.

=item B<sha1_base64($data, ...)>

=item B<sha256_base64($data, ...)>

=item B<sha384_base64($data, ...)>

=item B<sha512_base64($data, ...)>

Joins the arguments into a single string, and returns its
SHA-1/256/384/512 digest encoded as a Base64 string.

=back

I<OO style>

=over 4

=item B<$sha = Digest::SHA-E<gt>new($alg)>

Returns a new Digest::SHA object.  Permissible values for I<$alg>
are 1, 256, 384, and 512.  However, it's also possible to use common
string representations of the algorithm (e.g. "sha256", "SHA-384").
If the argument is missing, SHA-1 will be used by default.

Invoking "new" as an instance method will not cause a new object
to be created, but will simply reset the object to the initial
state associated with I<$alg>.  If the argument is missing, the
object will continue using the same algorithm that was selected at
creation.

=item B<$sha-E<gt>reset($alg)>

This method has exactly the same effect as I<$sha-E<gt>new($alg)>.
In fact, "reset" is just an alias for "new".

=item B<$sha-E<gt>hashsize>

Returns the number of digest bits for this object.  The values are
160, 256, 384, and 512 for SHA-1, SHA-256, SHA-384, and SHA-512,
respectively.

=item B<$sha-E<gt>clone>

Returns a duplicate copy of the I<$sha> object.

=item B<$sha-E<gt>add($data, ...)>

Joins the arguments into a single string, and uses it to update
the current I<$sha> digest state.  In other words, the following
statements have the same effect:

	$sha->add("a"); $sha->add("b"); $sha->add("c");
	$sha->add("a")->add("b")->add("c");
	$sha->add("a", "b", "c");
	$sha->add("abc");

=item B<$sha-E<gt>add_bits($data, $nbits)>

=item B<$sha-E<gt>add_bits($bits)>

Updates the current digest state by appending bits to it.  The
return value is the updated object itself.

The first form causes the most-significant I<$nbits> of I<$data>
to be appended to the stream.  The $data argument is in the customary
binary format used for Perl strings.

The second form takes an ASCII string of "0" and "1" characters as
its argument.  It's simply a convenient shorthand for

	$sha->add_bits(pack("B*", $bits), length($bits));

So, the following two statements do the same thing:

	$ctx->add_bits("111100001010");
	$ctx->add_bits("\xF0\xA0", 12);

=item B<$sha-E<gt>addfile(*FILE)>

Reads from I<FILE> until EOF, and appends that data to the current
$sha state.  The return value is the updated $sha object itself.

=item B<$sha-E<gt>dump($filename)>

Provides persistent storage of intermediate SHA states by writing
a portable, human-readable representation of the current state to
I<$filename>.  If the argument is missing, or equal to the empty
string, the state information will be written to stdout.

=item B<$sha-E<gt>load($filename)>

Returns a Digest::SHA object representing the intermediate SHA
state that was previously stored to I<$filename>.  If called as a
class method, a new object is created; if called as an instance
method, the object is reset to the state contained in I<$filename>.

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

=item B<$sha-E<gt>b64digest>

Returns the digest encoded as a Base64 string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>b64digest> if it's necessary to preserve
the original digest state.

=back

I<HMAC-SHA-1/256/384/512>

=over 4

=item B<hmac_sha1($data, $key)>

=item B<hmac_sha256($data, $key)>

=item B<hmac_sha384($data, $key)>

=item B<hmac_sha512($data, $key)>

Returns the HMAC-SHA-1/256/384/512 digest of I<$data>/I<$key>, with
the result encoded as a binary string.  Multiple $data arguments
are allowed, provided that $key is the final argument in the list.

=item B<hmac_sha1_hex($data, $key)>

=item B<hmac_sha256_hex($data, $key)>

=item B<hmac_sha384_hex($data, $key)>

=item B<hmac_sha512_hex($data, $key)>

Returns the HMAC-SHA-1/256/384/512 digest of I<$data>/I<$key>, with
the result encoded as a hexadecimal string.  Multiple $data arguments
are allowed, provided that $key is the final argument in the list.

=item B<hmac_sha1_base64($data, $key)>

=item B<hmac_sha256_base64($data, $key)>

=item B<hmac_sha384_base64($data, $key)>

=item B<hmac_sha512_base64($data, $key)>

Returns the HMAC-SHA-1/256/384/512 digest of I<$data>/I<$key>, with
the result encoded as a Base64 string.  Multiple $data arguments
are allowed, provided that $key is the final argument in the list.

=back

=head1 SEE ALSO

L<Digest::>, L<Digest::SHA1>

The Secure Hash Standard (FIPS PUB 180-2) can be found at:

http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

The Keyed-Hash Message Authentication Code (HMAC):

http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf

=head1 AUTHOR

Mark Shelor, E<lt>mshelor@comcast.netE<gt>

Many thanks to Gisle Aas, Julius Duque, Jeffrey Friedl, and Chris
Skiscim for their valuable comments and suggestions.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003 by Mark Shelor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
