use ExtUtils::MakeMaker;

my $I = pack("L", 0x01020304);
my $B = pack("N", 0x01020304);
my $L = pack("N", 0x04030201);

my @defines = ();
push(@defines, '-DSHA_BIG_ENDIAN') if $I eq $B;
push(@defines, '-DSHA_LITTLE_ENDIAN') if $I eq $L;
push(@defines, '-DNO_SHA_384_512') if $ARGV[0] =~ /^no/i;

my $define = join(" ", @defines);

WriteMakefile(
	'NAME'		=> 'Digest::SHA',
	'VERSION_FROM'	=> 'SHA.pm',
	'PREREQ_PM'	=> {},
	'AUTHOR'	=> 'Mark Shelor <mshelor@comcast.net>',
	'LIBS'		=> [''],
	'DEFINE'	=> $define,
	'INC'		=> '-I.',
);
