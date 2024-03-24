#!/usr/bin/perl
# $Intent: act w/ Love and Kindness $

# $Author: michelc $
# $Created-On: Wed, 2023-10-04 09:24:32 $
# $Last-Modified: Sun, 2023-10-29 18:12:15 $
# .-1! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"

package a;
use Exporter qw(import);
@EXPORT = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};
use strict;
use lib '/ipfs/QmWiovBJUxue8oZYFDV1zkDXubMaBtbXdrFCjCsXJSjrva';
use essential qw(version keyw);

use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');

printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------

use lib $ENV{HOME}.'/projects/benches/radiant/SHFIT/lib';

$\ = $/ || "\n";

if (__FILE__ eq $0) {
# -----------------------------------------------------------
#understand variable=value on the command line...
eval "\$$1='$2'"while $ARGV[0] =~ /^(\w+)=(.*)/ && shift;
# -----------------------------------------------------------

printf "--- %s${\}",${0}; # "}"
## TODO: place your code here

print "...";
exit $?;

}

sub import {
    my $caller = caller;
    no strict 'refs';
    *{$caller . '::a'} = \&a;
}


# vim: syntax=perl
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"
1; # $Source: /ipfs/QmYj4FdAh5DfXdu7pnHaWjkFHwxTVTX4i5CTyuVVYo3Qkd/a.pm $
