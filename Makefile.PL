use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $L = pack("L", 0x01020304);
my $N = pack("N", 0x01020304);

my $define = $L eq $N ? '-DSHA_BIG_ENDIAN' : '';
# $define .= ' -DNO_SHA_384_512';

WriteMakefile(
    'NAME'		=> 'Digest::SHA',
    'VERSION_FROM'	=> 'SHA.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'SHA.pm', # retrieve abstract from module
       AUTHOR     => 'Mark Shelor <mshelor@comcast.net>') : ()),
    'LIBS'		=> [''], # e.g., '-lm'
    'DEFINE'		=> $define,
#    'DEFINE'		=> '', # e.g., '-DHAVE_SOMETHING'
    'INC'		=> '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # 'OBJECT'		=> '$(O_FILES)', # link all the C files too
);
