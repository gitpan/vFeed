#!/usr/bin/perl
#
# $Id: vfeed.pl 3 2014-04-08 11:43:16Z gomor $
#
use strict;
use warnings;

use vFeed::DB;
use vFeed::Log;
use Data::Dumper;
use Getopt::Std;

my %opts;
getopts('f:m:c:', \%opts);

my $method = $opts{m} || 'get_cve';
my $cve = $opts{c} || 'CVE-2014';

my $log = vFeed::Log->new;

my $vfeed = vFeed::DB->new(
   log => $log,
);
if (defined($opts{f})) {
   $vfeed->file($opts{f});
}

$vfeed->init;

#
# Do your job
#
my $db_version = $vfeed->db_version;
print "[+] vFeed db_version: $db_version\n\n";

my $data = $vfeed->$method($cve);
print Dumper($data),"\n";

$vfeed->post;
