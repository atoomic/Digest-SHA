use ExtUtils::MakeMaker;

my @defines = ('-DSHA_PERL_MODULE');

# push(@defines, '-DNO_SHA_384_512');
# push(@defines, '-DSHA_THREAD_SAFE');

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
