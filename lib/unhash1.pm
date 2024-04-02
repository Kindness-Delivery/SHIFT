package unhash;
use Exporter qw(import);
our @EXPORT = qw(unhash);

use Encode qw(decode);

use YAML::XS qw(Dump);
use Crypt::Digest;
our @ISA = qw(Crypt::Digest);

use lib $ENV{RADIANT}.'/lib';
sub DEBUG {};
use IDE; our $exclude = [82,84,88,89,90,98,104,108,116,120];

if (__FILE__ eq $0) {
   my $seed = pack'H32','750b7925-873c-4d2e-9bc0-a151368df700' =~ tr/-//dr;
   my $pass = ask_pass('rainbowsecret','rainbow passcode');
   my $mod = 32749 || 16381 || 8171;
   my $unhash = unhash->new($seed,$pass,$mod);
   printf "mod: %s\n",$unhash->{'mod'};
   printf "seed: %s\n",encode_uuid($unhash->{'seed'});
   my $test = $unhash->{ini}->clone();
   DEBUG "test: %s",$test->hexdigest();
   my $r = 0;
   while (1) {
      $r++;
      my $xm = int(rand$mod);
      next if (exists $unhash->{cache}{$xm});
      my $p = int(rand$mod);

      my $n = $unhash->unhash($p,$xm);
      my $j = $unhash->size();
      my $q = unpack'V',KH($seed,$pass,$n) ;
      my $m = $q % $mod;
      DEBUG "%-5s (hash(n=%10d)=q=%10d) %% %d = %5d =? %-5d; j=%s",$r,$n,$q,$mod,$m,$xm,$j;
      die if $m != $xm;
      last if $j >= $mod;
   }

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
   sub encdoe_uuid($@) {
   }

}

sub new {
  my ($class, $seed, $pass,$mod) = (@_);
  my $ini = Crypt::Digest->new('SHA256');
  $ini->add($seed //= pack'H32','e491ec6cc18345f79a7838601864d927' =~ tr/-//dr);
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

sub size {
  my $self = shift;
  return scalar keys %{$self->{cache}};
}

sub unhash { # Ex. my $p = $unhash->unhash($expected);
  my ($self,$iv,$x) = @_;
  $x //= $$ % $self->{mod}; # expected hash value
  my $unhash = $self->{cache};
  return $unhash->{$x} if (exists $unhash->{$x});
  my $mod = $self->{mod} // 16381;
  my $ini = $self->{ini};
  if (!defined $ini) {
     DEBUG "--- # unhash.self: %s...",Dump($self);
  } else {
     my $test = $ini->clone();
     DEBUG " seed: %s",encode_uuid($self->{seed});
     DEBUG " pass: %s",$self->{pass};
     DEBUG "ini.digest: %s",$test->hexdigest();
  }
  my ($i,$j) = (0,0);  # total iteration, found matches
  my $n = $iv //= rand($mod); # IV (head)
  my $p = $iv; 
  my $nmax= 10 * $mod;
  my %seen = ();
  # ∀ m ∈ [0,mod[ ∃ p / h(p)%mod = m
  DEBUG decode('UTF-8',"∀ m=%d ∈ [0,mod[ ∃ p / h(p)%%%d = m"),$x,$self->{mod};
  while($j < $mod) {
     my $h = $ini->clone()->add($n)->digest();
     $n = unpack'V',$h;
     my $m = $n % $mod;
     if (! $unhash->{$m}) {
        DEBUG decode('UTF-8',"x: %04d ⟼  p: %s, n: %s, m: %s, j: %s"),$x,$p,$n,$m,$j;
        $unhash->{$m} = $p;
        $j++;
        if ($m == $x) { # expected value
           DEBUG "m = %s == x; (p=%s, n=%s, %s %% %s)",$m,$unhash->{$m}, $n,$n,$m;
           last;
        } 
     } elsif (!$seen{$n}) {
        $seen{$n} = $p;
     } else {
        while($seen{$n}) { $n++; }
        last if scalar keys %seen > $nmax;
        DEBUG "m = %s; n=%s",$m,$n;
     }
     $p = $n; $i++;
  }
  DEBUG decode('UTF-8'," i:%6d,j:%5d, x=%5d ⟼  p=%11d, n:%10d / KH(...,n) = x"),$i,$j,$x,$p,$n;
  return $unhash->{$m} // $p;

}
sub ask_pass {
   open ASK,sprintf'/usr/bin/systemd-ask-password --keyname="%s" --accept-cached "%s"|',shift,shift//'passcode';
   chomp(my $pass = <ASK>);
   return $pass;
}

sub encode_uuid {
  my $sep = ($_[-1] =~ m/^[^0-9A-Fa-f]$/) ? pop : '-';
  my $data = join'',@_;
  my $len = length($data);
  my $uuid = join$sep,unpack'H6H6H4H4H12H*',$data;
     $uuid =~ s/$sep+$//;
  return $uuid;
}

