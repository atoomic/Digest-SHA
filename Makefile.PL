use ExtUtils::MakeMaker;

my @defines = ('-DSHA_PERL_MODULE');
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
