#!perl
BEGIN { if (__FILE__ eq $0) { require lib; lib->import("/ipfs/$ENV{QMLIB}"); } }
# $Intent: act w/ Love and Kindness $

# $Author: michelc $
# $Created-On: Fri, 2023-12-08 18:09:18 $
# $Last-Modified: Fri, 2023-12-08 18:23:56 $
# .-2! echo "\# \$Created-On: $(date -d @$(stat -c \%Y %~1)  +'\%a, \%Y-\%m-\%d \%T') \$"
# .-2! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -n -w % -Q)/%:t \$"

# export QMLIB=$(cd radiant/SHIFT 1>/dev/null; ipfs add -r lib -Q)
package public;
our @EXPORT = qw(getPublicKey);

if (__FILE__ eq $0) {
   my $keyid = 'public';
   my $intent = 'encrypt public data';
   my $info = { &getPublicKey($keyid,$intent) };
   my $pkp = $info->{public};
   printf "pkp: %s # (%s)\n",$pkp,$info->{name};
   die if ($pkp ne 'ZXvYTNUJm8aCysRzkmBmkhzYVMGHvmwUKmKx8pswKR6fG');
   exit $?;
}

sub getPublicKey {
   use broker qw(KH EC);
   my $msg = sprintf 'This is key (%s) to the %s: no real secret here',@_;
   my $nosecret = &KH($msg);
   my $pkp_raw = &EC($nosecret);
   if (wantarray) {
      use encode qw(encode_mbase58);
      use misc::keyname qw(firstname);
      my $name = firstname($pkp_raw);
      my $pkp = encode_mbase58($pkp_raw);
      my $skp = encode_mbase58($nosecret);
      return  name => $name, public=> $pkp, private => $skp;
   } else {
      return $pkp_raw;
   }
}

sub import {
    my $caller = caller;
    my $pkg = shift;
    no strict 'refs';
    for (@EXPORT) {
      *{$caller . "::$_"} = \&{$_};
    }
    for (@_) {
      *{$caller . "::$_"} = \&{$_};
    }
}

1; # $Source: /ipfs/Qmdj9TNLg8qRFM3ZJB1T79XMGsCfVGXGDM4CwXiXWVqNnJ/public.pm $
