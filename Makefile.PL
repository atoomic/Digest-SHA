#use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $L = pack("L", 0x01020304);
my $N = pack("N", 0x01020304);

my $define = $L eq $N ? '-DSHA_BIG_ENDIAN' : '';
# $define .= ' -DNO_SHA_384_512';

WriteMakefile(
    'NAME'  => 'Digest::SHA',
    'VERSION_FROM' => 'SHA.pm',
    'PREREQ_PM'  => {'Digest::base' => '1.00'},
    ($] >= 5.005 ?
      (ABSTRACT_FROM => 'SHA.pm',
       AUTHOR     => 'Mark Shelor and Julius C. Duque') : ()),
    'LIBS'  => [''], # e.g., '-lm'
    'DEFINE'  => $define,
    'dist' => {'COMPRESS' => 'gzip -9f', 'SUFFIX' => 'gz'},
    'INC'  => '-I.', # e.g., '-I. -I/usr/include/other'
 # Un-comment this if you add C files to link with later:
    # 'OBJECT'  => '$(O_FILES)', # link all the C files too
);

