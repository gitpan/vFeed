#
# $Id: Makefile.PL 3 2014-04-08 11:43:16Z gomor $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME => 'vFeed',
   LICENSE => 'artistic',
   VERSION_FROM => 'lib/vFeed.pm',
   ABSTRACT_FROM => 'lib/vFeed.pm',
   AUTHOR => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM => {
      Class::Gomor => 0,
      LWP::UserAgent => 0,
      Digest::SHA1 => 0,
      Archive::Tar => 0,
   },
   EXE_FILES => [ 'bin/vfeed.pl', ],
   MIN_PERL_VERSION => '5.6.1',
);
