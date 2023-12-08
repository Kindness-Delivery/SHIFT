#!perl

# .+2! echo "use lib '/ipfs/$(cd radiant/SHIFT 1>/dev/null; ipfs add -r lib -Q)';"
# export QMLIB=$(cd radiant/SHIFT 1>/dev/null; ipfs add -r lib -Q)
use lib '/ipfs/QmNyizEm6i8yp1xsy9VT6NB9MqStKzNnHh2X48ipdbDx4f';
use lib "/ipfs/$ENV{QMLIB}";
#require lib; lib->import("/ipfs/$ENV{QMLIB}");
use public;

DUT: {
   my $keyid = 'public';
   my $intent = 'encrypt public data';
   my $info = { &getPublicKey($keyid,$intent) };
   my $pkp = $info->{public};
   printf "pkp: %s # (%s)\n",$pkp,$info->{name};
   die if ($pkp ne 'ZXvYTNUJm8aCysRzkmBmkhzYVMGHvmwUKmKx8pswKR6fG');
}
exit $?;
