package unhash;
use Exporter qw(import);
our @EXPORT = qw(unhash);

use YAML::XS qw(Dump);
use Crypt::Digest;
our @ISA = qw(Crypt::Digest);
our $mod = 32749 || 16381 || 8171;
sub DEBUG {};

if (__FILE__ eq $0) {
   my $seed = '750b7925-873c-4d2e-9bc0-a151368df700';
   my $pass = 'secret password';
   my $unhash = unhash->new($seed,$pass,$mod);
   DEBUG "new: %s",Dump($unhash);
   printf "mod: %s\n",$unhash->{'mod'};
   printf "seed %s\n",encode_uuid($unhash->{'seed'});

   my $xm = int(rand$mod);
   my $p = int(rand$mod);

   my $n = $unhash->unhash($p,$xm);
   my $q = unpack'V',KH(pack('H32',$seed =~ tr/-//dr),$pass,$n) ;
   my $m = $q % $mod;
   DEBUG "// (h(n:%10d)=%10d) %% %d = %4d =? %4d",$n,$q,$mod,$m,$xm;
   die if $m != $xm;

   exit $?;

   sub KH($@) { # KH for verification purpose
      my $alg = 'SHA256';
      my $data = join'',@_;
      my $msg = Crypt::Digest->new($alg) or die $!;
      $msg->add($data);
      my $hash = $msg->digest();
      return $hash;
   }
   sub encode_uuid {
   }

}

sub new {
  my ($class, $seed, $pass,$mod) = (@_);
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
  my $ini = $self->{ini}->clone();
  my ($i,$j) = (0,0);  # total iteration, found matches
  my $n = $iv //= rand($mod); # IV (head)
  my $p = $iv; 
  my %seen = ();
  # ∀ m ∈ [0,mod[ ∃ p / h(p)%mod = m
  DEBUG ('UTF-8',"∀ m=%d ∈ [0,mod[ ∃ p / h(p)%%%d = m"),$x,$self->{mod};
  while($j < $mod) {
   my $h = $ini->add($n)->digest();
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

sub encode_uuid {
  my $sep = ($_[-1] =~ m/^[^0-9A-Fa-f]$/) ? pop : '-';
  my $data = join'',@_;
  my $len = length($data);
  my $uuid = join$sep,unpack'H6H6H4H4H12H*',$data;
     $uuid =~ s/$sep+$//;
  return $uuid;
}

