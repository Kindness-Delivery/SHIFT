#
# $Intent: kindly provide fnumber for a given key $
#
# Note:
#   This work has solely been done during my own spare time
# 
# -- PublicDomain CC0 drit, 2022; https://creativecommons.org/publicdomain/zero/1.0/legalcode --
#
BEGIN { if (__FILE__ eq $0) { require lib; lib->import("/ipfs/$ENV{QMLIB}"); } }
# export QMLIB=$(cd radiant/SHIFT 1>/dev/null; rm~ 1>/dev/null; ipfs add -r lib -Q)
#
package encode::fnumber;
use strict;
# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# -----------------------------------------------------------------------

if (__FILE__ eq $0) {
  my $pkb = 'ZDyTFwMwzkewGFyAcWKcgd68vc875QAmksxSNNfCaL3uh';
  if (1) {
    require botname; botname->import('firstname');
    printf "radix: %s\n",scalar@{$botname::wordlists->{fnames}};
    printf "keyname: %s\n",firstname($pkb);
  }

   use encode qw(decode_mbase58);
   my $pkb_raw = &decode_mbase58($pkb);
   my $fn=&fnumber($pkb_raw) % 9698;
   printf "fnumber: %s\n",$fn;
   die if $fn != 1182;
   exit $?;
}

sub fnumber(;) {
  use Crypt::Digest::SHA256 qw(sha256);
  my $fprint = sha256(@_);
  my $funiq = substr($fprint,-7,6); # 6 chars (except last)
  my $quniq = unpack'Q>', pack('C2',0,0).$funiq;
  return $quniq;
}
sub import {
    my $caller = caller;
    no strict 'refs';
    *{$caller . '::fnumber'} = \&fnumber;
}
# # vim: syntax=perl
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -n -w % -Q)/%:t \$"
# ------------------------------------------------------------------------------
1; # $Source: /ipfs/QmdS9QFGNGULasnoSQjkSh7rwf9in2B66MGZg7efbo2CW9/fnumber.pm $
