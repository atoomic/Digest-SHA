use ExtUtils::MakeMaker;

my $L = pack("L", 0x01020304);
my $N = pack("N", 0x01020304);

my @defines = ();
push(@defines, '-DSHA_BIG_ENDIAN') if $L eq $N;
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
