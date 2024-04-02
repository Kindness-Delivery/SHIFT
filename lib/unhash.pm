
package unhash;
our @EXPORT = qw(unhash);

use Encode;
my $asso = decode('UTF-8','⟼ ');
use YAML::XS qw(Dump);
use lib "$ENV{XDG_CACHE_HOME}/qmlib/QmaJppNFbBRnsvHbyaFDb5trcnvXrJUqSgWu5YmMJKRbPH"; # Charles 👆  8 radiant/SHIFT/lib
#use lib "$ENV{XDG_CACHE_HOME}/qmlib/QmarGgedn853dt5WYfgPW1nMLAc9kRfsSMYZkuzdLJiWg4"; # Douglas 🍞  853 SWPoC/lib
#use lib "$ENV{RADIANT}/lib";
#use lib "$ENV{SITE}/lib";
use encode;
sub DEBUG{};
my $j = 0; 
use IDE;
#our$exclude = [31,51,72];
#ur$observe = [71];
our $mod = 32749 || 16381 || 8171;

use Crypt::Digest;
our @ISA = qw(Crypt::Digest);


if (__FILE__ eq $0) {
  my $seed = '750b7925-873c-4d2e-9bc0-a151368df700';
  my $pass = ask_pass('rainbowsecret','rainbow passcode');
  my $unhash = unhash->new($seed,$pass,$mod);
  DEBUG "new: %s",Dump($unhash);
  printf "mod: %s\n",$unhash->{'mod'};
  printf "seed %s\n",encode_uuid($unhash->{'seed'});

  my $r = 0;
  while (1) {
    $r++;
    my $xm = int(rand$mod);
    my $p = int(rand$mod);


    my $n = unhash->unhash($p,$xm);
    my $q = unpack'V',KH(pack('H32',$seed =~ tr/-//dr),$pass,$n) ;
    my $m = $q % $mod;
    DEBUG "// (h(n:%10d)=%10d) %% %d = %4d =? %4d",$n,$q,$mod,$m,$xm;
    #printf "eq%d: x=%d p=%d m=%d\n",$i,$xm,$p,$m;
    die if $m != $xm;
    last if $j == $mod; # done all the numbers from 0 to mod-1!
  }
  printf "r: %d\n",$r; # number of runs
  exit $?;
  sub KH($@) { # KH for verification purpose
    use Crypt::Digest qw();
    my $alg = 'SHA256';
    my $data = join'',@_;
    my $msg = Crypt::Digest->new($alg) or die $!;
    $msg->add($data);
    my $hash = $msg->digest();
    return $hash;
  }

}


sub new {
  my ($class, $seed, $pass,$mod) = @_;
  my $ini = Crypt::Digest->new('SHA256');
  $ini->add(my $seed //= pack'H32','e491ec6cc18345f79a7838601864d927' =~ tr/-//dr);
  $ini->add($pass) if (defined $pass);
    my $self = {
        seed => $seed,
        pass => $pass,
        ini => $ini,
        mod => $mod,
        cache => {},
    };
    bless $self, $class;
    return $self;
}

sub unhash { # Ex. my $p = $unhash->unhash($expected);
  my ($self,$iv,$x) = @_;
  $x //= $$ % $self->{mod}; # expected hash value
  my $unhash = $self->{cache};
  return $unhash->{$x} if (exists $unhash->{$x});
  my $mod = $self->{mod} // 16381;
  my $ini = $self->{ini};
  my ($i,$j) = (0,0);  # total iteration, found matches
  my $n = $iv //= rand($mod); # IV (head)
  my $p = $iv; 
  my %seen = ();
  # ∀ m ∈ [0,mod[ ∃ p / h(p)%mod = m
  DEBUG decode('UTF-8',"∀ m=%d ∈ [0,mod[ ∃ p / h(p)%%%d = m"),$x,$self->{mod};
  while($j < $mod) {
   my $h = $ini->clone()->add($n)->digest();
   $n = unpack'V',$h;
   my $m = $n % $mod;
   if (! $unhash->{$m}) {
      DEBUG "x: %04d $asso p: %s, n: %s, m: %s, j: %s",$x,$p,$n,$m,$j;
      $unhash->{$m} = $p;
      $j++;
      if ($m == $x) { # expected value
         last;
      } 
   } elsif (!$seen{$n}) {
      $seen{$n} = $p;
   } else {
      while($seen{$n}) { $n++; }
   }
   $p = $n; $i++;
  }
  DEBUG " i:%6d,j:%5d, x=%5d $asso p=%11d, n:%10d / KH(...,n) = x",$i,$j,$x,$p,$n;
  return $unhash->{$m} // $p;

}

{
my %unhash = (); # /!\ only valid for one seed+pass
sub _unhash { # Ex. my $i = unhash($seed,$pass,$p,$m,$mod);
  my $mod = pop // 16381 ;
  my $unhash = $unhash{$mod} //= {};
  # unhash a small number ...
  if (exists $unhash->{$_[3]}) {
    return $unhash->{$_[3]};
  } 
  use Crypt::Digest qw();
  my $ini = Crypt::Digest->new('SHA256');
  $ini->add(my $seed = shift // pack'H32','e491ec6cc18345f79a7838601864d927' =~ tr/-//dr);
  DEBUG "seed: %s",unpack'H*',$seed;
  if (1) {
    my $pass = shift; #$_[0]; delete $_[0] && shift;
    $ini->add($pass);
  }
  my $i = 0;  # total iteration
  my $j = 0;  # found matches
  my $n = shift // rand($mod); # IV (head)
  my $p = $n; 
  my $x = shift // $$ % $mod; # expected hash value
  my %seen = ();
  # ∀ m ∈ [0,mod[ ∃ p / h(p)%mod = m
  DEBUG decode('UTF-8',"∀ m=%d ∈ [0,mod[ ∃ p / h(p)%%%d = m"),$x,$mod;
  while($j < $mod) {
   my $h = $ini->clone()->add($n)->digest();
   $n = unpack'V',$h;
   my $m = $n % $mod;
   if (! $unhash->{$m}) {
      DEBUG "x: %04d $asso p: %s, n: %s, m: %s, j: %s",$x,$p,$n,$m,$j;
      $unhash->{$m} = $p;
      $j++;
      if ($m == $x) { # expected value
         last;
      } 
   } elsif (!$seen{$n}) {
      $seen{$n} = $p;
   } else {
      while($seen{$n}) { $n++; }
   }
   $p = $n; $i++;
  }
  DEBUG " i:%6d,j:%5d, x=%5d $asso p=%11d, n:%10d / KH(...,n) = x",$i,$j,$x,$p,$n;
  return $unhash->{$m} // $p;
}
}



sub ask_pass {
   open ASK,sprintf'/usr/bin/systemd-ask-password --keyname="%s" --accept-cached "%s"|',shift,shift//'passcode';
   chomp(my $pass = <ASK>);
   return $pass;
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

1;
