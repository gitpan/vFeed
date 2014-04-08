#
# $Id: DB.pm 6 2014-04-08 12:31:37Z gomor $
#
package vFeed::DB;
use strict;
use warnings;

use base qw(Class::Gomor::Array);
our @AS = qw(
   file
   log
   _dbh
   _prepared
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

use vFeed;

use DBI;
use Data::Dumper;

use FindBin qw($Bin);
use LWP::UserAgent;
use Digest::SHA1;
use Archive::Tar;

sub new {
   my $self = shift->SUPER::new(
      _dbh => 0,
      @_,
   );

   if (!defined($self->log)) {
      die("[-] ".__PACKAGE__.": You must provide a log object\n");
   }

   return $self;
}

sub init {
   my $self = shift;

   my $log = $self->log;

   my $file = $self->file;
   if (!defined($file)) {
      for ("$Bin/", "$Bin/../db/") {
         if (-f $_.'vfeed.db') {
            $file = $_.'vfeed.db';
            last;
         }
      }
   }

   if (!defined($file)) {
      $log->fatal("No database file found");
   }
   elsif (!-f $file) {
      $log->fatal("Database file not found [$file]: $!");
   }

   $self->file($file);

   $log->verbose("Using database file: ".$self->file);

   my $dbh = DBI->connect(
      "dbi:SQLite:dbname=".$self->file, '', '', {
      RaiseError => 0,
      PrintError => 0,
      AutoCommit => 0,
      InactiveDestroy => 1,
      HandleError => sub {
         my ($errstr, $dbh, $arg) = @_;
         # Let's keep fatal() for all errors as a debugging mechanism for now
         $log->fatal("Database error: [$errstr]");
         return 1;
      },
   }) or $log->fatal("Database error: [".$DBI::errstr."]");
   $self->_dbh($dbh);

   my $p = $dbh->prepare(qq{SELECT count(*) from stat_vfeed_kpi});

   # We fail if stat_vfeed_kpi is empty
   # The problem may be solved by using the latest DBD::SQLite module
   my $rv = $p->execute;
   my $h = $p->fetchrow_hashref;
   my ($k, $v) = each(%$h);
   if (! ($v > 0)) {
      $log->fatal("Unable to find valid vFeed tables");
   }

   # Create prepared statements
   $self->_prepare;

   return 1;
}

sub _prepare {
   my $self = shift;

   my $dbh = $self->_dbh;

   my %select = (
      db_version => qq{SELECT db_version FROM stat_vfeed_kpi},
      total_cve => qq{SELECT total_cve FROM stat_vfeed_kpi},
      latest_cve => qq{SELECT * FROM stat_new_cve},

      # Information
      get_cve => qq{SELECT * FROM nvd_db WHERE cveid LIKE ?},
      get_cpe => qq{SELECT * FROM cve_cpe WHERE cveid LIKE ?},
      get_cwe => qq{SELECT * FROM cve_cwe WHERE cveid LIKE ?},
      get_capec => qq{SELECT * FROM cwe_capec WHERE cweid LIKE ?},
      get_category => qq{SELECT * FROM cwe_category WHERE cweid LIKE ?},
      get_iavm => qq{SELECT * FROM map_cve_iavm WHERE cveid LIKE ?},

      # References
      get_refs => qq{SELECT * FROM cve_reference WHERE cveid LIKE ?},
      get_scip => qq{SELECT * FROM map_cve_scip WHERE cveid LIKE ?},
      get_osvdb => qq{SELECT * FROM map_cve_osvdb WHERE cveid LIKE ?},
      get_certvn => qq{SELECT * FROM map_cve_certvn WHERE cveid LIKE ?},
      get_bid => qq{SELECT * FROM map_cve_bid WHERE cveid LIKE ?},

      # Perl version only
      get_cve_from_cpe => qq{SELECT * FROM cve_cpe WHERE cpeid LIKE ?},
   );

   my %prepared = ();
   for my $this (keys %select) {
      my $select = $dbh->prepare($select{$this});
      $prepared{$this} = $select;
   }

   $self->_prepared(\%prepared);

   return 1;
}

sub run {
   my $self = shift;
   return $self;
}

sub db_version {
   my $self = shift;

   my $log = $self->log;

   my $dbh = $self->_dbh;
   my $s = $self->_prepared->{db_version};
   my $rv = $s->execute;
   my $h = $s->fetchall_arrayref;

   if (defined($h->[0]) && defined($h->[0][0])) {
      my $version = $h->[0][0];
      $version = sprintf("%08d", $version);
      return $version;
   }

   $log->fatal("db_version not found");
   return;
}

sub latest_cve {
   my $self = shift;

   my $dbh = $self->_dbh;
   my $s = $self->_prepared->{latest_cve};
   my $rv = $s->execute;
   my $h = $s->fetchall_hashref('new_cve_id');

   return $h;
}

sub _get_info {
   my $self = shift;
   my ($info, $cve) = @_;

   my $log = $self->log;

   if (!defined($cve)) {
      $log->error("You MUST provide CVE argument");
      return;
   }

   my $dbh = $self->_dbh;
   my $s = $self->_prepared->{$info};
   my $rv = $s->execute("\%$cve\%");
   my $h = $s->fetchall_hashref('cveid');

   return $h;
}

sub get_cve {
   my $self = shift;
   return $self->_get_info('get_cve', @_);
}

sub get_cpe {
   my $self = shift;
   return $self->_get_info('get_cpe', @_);
}

sub get_cwe {
   my $self = shift;
   return $self->_get_info('get_cwe', @_);
}

sub get_capec {
   my $self = shift;
   return $self->_get_info('get_capec', @_);
}

sub get_category {
   my $self = shift;
   return $self->_get_info('get_category', @_);
}

sub get_iavm {
   my $self = shift;
   return $self->_get_info('get_iavm', @_);
}

sub get_cve_from_cpe {
   my $self = shift;
   my ($cpe) = @_;

   my $log = $self->log;

   if (!defined($cpe)) {
      $log->error("You MUST provide CPE argument");
      return;
   }

   my $dbh = $self->_dbh;
   my $s = $self->_prepared->{get_cve_from_cpe};
   my $rv = $s->execute("\%$cpe\%");
   my $h = $s->fetchall_hashref('cveid');

   return $h;
}

sub post {
   my $self = shift;

   if ($self->_dbh) {
      $self->_dbh->disconnect;
   }

   return 1;
}

sub update {
   my $self = shift;

   my $log = $self->log;

   my $ua = LWP::UserAgent->new;
   $ua->timeout(10);
   $ua->env_proxy;
   $ua->agent("Perl::vFeed ".$vFeed::VERSION);

   my $dbFile = $self->file;

   my $url = "http://www.toolswatch.org/vfeed/update.dat";
   my $db = $ua->get($url);
   if ($db->is_success) {
      (my $sha1 = $db->decoded_content) =~ s/^.*,(.*)$/$1/;
      chomp($sha1);
      open(my $in, '<', $dbFile) or $log->fatal(
         "open1: $dbFile: $!"
      );
      my $old = Digest::SHA1->new;
      $old->addfile($in);
      my $oldsha1 = $old->hexdigest;
      CORE::close($in);
      if ($oldsha1 ne $sha1) {
         $log->info("Database require updating, download in progress...");
         $self->_updateDb($ua);
      }
      else {
         $log->info("Database already up-to-date");
      }
   }
   else {
      $log->fatal("GET [$url]: ". $db->status_line);
   }

   return 1;
}

sub _updateDb {
   my $self = shift;
   my ($ua) = @_;

   my $log = $self->log;

   my $dbFile = $self->file;

   my $url = "http://www.toolswatch.org/vfeed/vfeed.db.tgz";
   my $db = $ua->get($url);
   if ($db->is_success) {
      my $tgz = "$dbFile.tgz";
      if (-f $tgz) {
         $log->fatal("$tgz file already exists: we will not overwrite it");
      }
      open(my $out, '>', $tgz) or $log->fatal(
         "open2: $dbFile: $!"
      );
      print $out $db->decoded_content;
      CORE::close($out);

      my $tar = Archive::Tar->new;
      $tar->read($tgz);
      $tar->extract;

      unlink($tgz);
   }
   else {
      $log->fatal("GET [$url]: ".$db->status_line);
   }
   $log->info("Update complete for [$dbFile]");

   return 1;
}

1;

__END__

=head1 NAME

vFeed::DB - main access to vFeed database

=head1 DESCRIPTION

=head1 METHODS

=over 4

=item B<init>

=item B<db_version>

=item B<get_cpe>

=item B<get_cve>

=item B<get_capec>

=item B<get_category>

=item B<get_cwe>

=item B<get_iavm>

=item B<get_cve_from_cpe>

=item B<latest_cve>

=item B<run>

=item B<update>

=item B<post>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2014, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
