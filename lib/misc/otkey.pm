#!perl
# $Intent: kindly deliver one time keys $
#
# $Created-On: Fri, 2023-11-12 08:06:59 $
# $Last-Modified: Fri, 2023-11-17 10:15:52 $
# .-1! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"
BEGIN { if (__FILE__ eq $0) { require lib; lib->import("/ipfs/$ENV{QMLIB}"); } }

package misc::otkey;
use strict;
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
use version;
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');
printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------


if (__FILE__ eq $0) {
  #understand variable=value on the command line...
  eval "\$$1='$2'"while $ARGV[0] =~ /^(\w+)=(.*)/ && shift;

  use misc::pass;
  my $keyset = [];
  my $pass = &read_pass('otkey passcode:');
  $keyset->[1] = { &otkey($pass,1) };
  $keyset->[2] = { &otkey($pass,2) };
  printf "seed1: %s\n",$keyset->[1]{seed};
  printf "seed2: %s\n",$keyset->[2]{seed};

  printf "key1: %s\n",$keyset->[1]{otkey};
  printf "key2: %s\n",$keyset->[2]{otkey};
  exit $?;
}
sub otkey { # Ex. my $otp = &otkey($pass,$cnt);
  use secrets;
  use MIME::Base64 qw(encode_base64);
  use misc::bro qw(KH KDF KM);
  use misc::enc qw(encode_base58f);
  #y $intent="one time seed";
  my $pass = shift;
  my $entropy = KH('entropy',$pass,$secrets->{entropy_uuid}||'3b032cdc-ef84-4783-8c5b-5bf835a86fb4');
  my $seed = KDF('otp-seed',$pass,$entropy,$VERSION);
  my $otk = KM($seed,@_);
  return wantarray ? (
        entropy => encode_base64($entropy,''),
        seed => encode_base64($seed,''),
        otkey => 'Z'.encode_base58f($otk)
    ) : $otk;
}
sub import {
    my $caller = caller;
    no strict 'refs';
    *{$caller . '::otkey'} = \&otkey;
}
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"
1; # $Source: /ipfs/QmYRtTrN7KE4C4JE5UyTwpzpfyQgcTTAYPQRDtAnFWw1eK/otkey.pm $
