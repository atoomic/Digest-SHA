use ExtUtils::MakeMaker;
use Getopt::Std;

my %opts;
getopts('tx', \%opts);

my @defines = ('-DSHA_PERL_MODULE');

push(@defines, '-DSHA_THREAD_SAFE') if $opts{'t'};
push(@defines, '-DNO_SHA_384_512')  if $opts{'x'};

my $define = join(' ', @defines);

WriteMakefile(
	'NAME'		=> 'Digest::SHA',
	'VERSION_FROM'	=> 'SHA.pm',
	'PREREQ_PM'	=> {},
	'AUTHOR'	=> 'Mark Shelor <mshelor@cpan.org>',
	'LIBS'		=> [''],
	'DEFINE'	=> $define,
	'INC'		=> '-I.',
	'NO_META'	=> 1,
	'EXE_FILES'	=> [ 'shasum' ]
);
