#
# Intent:
#  spot package gives current location on the space-time hyper-plane (surface).
#
# Note:
#   This work has been done during my time freelancing
#   for PaladinAI at Toptal as Doctor I·T
#
#   if you'd like more work to be done check us at
#   [upwork](https://www.upwork.com/freelancers/~01cd05dc18152b7a50)
#   for competitive rate
# 
# -- PublicDomain CC0 drit, 2021; https://creativecommons.org/publicdomain/zero/1.0/legalcode --
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }
#
package spot;
use Exporter qw(import);
# Subs we export by default.
@EXPORT = qw();
# Subs we will export if asked.
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};

use strict;
use YAML::XS qw();
use essential qw(version);

#use NOLOG qw($LOG debug);
sub intent {};
sub returning {};
#use profiler qw(intent returning);
use api qw(getParams getEnv);

our $seed = undef;

sub INFO {};
use IDE;
our $skip = [62,129];
sub DEBUG{};

# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');
INFO "--- # %s: %s %s",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------



sub get_spot { # Ex. my $spot = &get_spot($ip,$tics);
  my ($dotip,$tics) = @_;
  #my $c4 = pack'C4',split('\.',$dotip));
  #my $nip = unpack('N',$c4);
  my $spot = pack'C4N',split('\.',$dotip),int($tics);
  return $spot;
}



sub getspot { # my $spot = &getspot($env);
  intent "get current physical location in space-time"; 
  use Time::HiRes qw(time clock_gettime clock_getres CLOCK_MONOTONIC);
  use api qw(getQueryParams);
  my $params = &getQueryParams();
  DEBUG "params: %s---",YAML::XS::Dump($params);
  my $tic = $params->{tic} || time;
  #printf "tics: %.24f\n",$tic;
  my $pubip = &get_publicip();
  my $nip =  &getnip();
  my $pip =  $nip||unpack('N',pack'C4',split('\.',$pubip));
  my $city =  &getCity($pip);
  my $country =  &getCountry($pip);
  my $node = &getNode($pip);

  my $clockmono   = $params->{clock} || clock_gettime(CLOCK_MONOTONIC);
  DEBUG "clockmono: %x",$clockmono;
  my $resolution = clock_getres(CLOCK_MONOTONIC);
  my $boot=$tic - $clockmono;
  # compute spot
  my $spot = int($clockmono) ^ $nip;

  use misc qw(khash);
  my $salt= $params->{salt} || $$; # overwritable for test 
  my $md5 = &khash('MD5',$salt,$spot);
  my $hash = sprintf "f%s#%x",unpack('H*',$md5),$salt;
  if ($pubip eq '0.0.0.0') {
    my $json = { error => '410 public ip unknown', usage => 'getspot.html' };
    #returning;
    return wantarray ? (1,$json) : $json;  
  } else {
    my $json = {
      tic => $tic,
      nip => $nip,
      city => $city,
      country => $country,
      dotip => join('.',unpack('C4',pack'N',$nip)),
      pubip => $pubip,
      node => $node,
      boot => $boot,
      clockmono => $clockmono,
      spot => $spot,
      hash => $hash,
      usage => 'getspot.html',
      geoloc => 'by doctor-it',
      status => '200 OK'
    };
    #returning;
    return wantarray ? (0,$json) : $json;  
  }

}

sub getnip { # my $nip = &getnip();
  intent 'numerical IP address';
  #y $callee = (&callee())[0];
  use api qw(getEnv); my $env = $_[0] || &getEnv();
  
  my $dotip;
  if (exists $env->{HTTP_CLIENT_IP}) {
    $dotip = $env->{HTTP_CLIENT_IP};
  } elsif (exists $env->{HTTP_X_REAL_IP}) {
    $dotip = $env->{HTTP_X_REAL_IP};
  } elsif (exists $env->{HTTP_X_FORWARDED_FOR}) {
    $dotip = $env->{HTTP_X_FORWARDED_FOR};
  } elsif (exists $env->{REMOTE_ADDR}) {
    $dotip = $env->{REMOTE_ADDR};
  } else {
    $dotip = '0.0.0.0';
  }
  DEBUG "dotip: %s",$dotip;
  my $nip = unpack'N',pack'C4',split('\.',$dotip);
  DEBUG "nip: %08x",$nip;
  #returning;
  return $nip;
}

sub get_ip {
  use api qw(getEnv); my $env = $_[0] || &getEnv();
  my $dotip;
  if (exists $env->{HTTP_CLIENT_IP}) {
    $dotip = $env->{HTTP_CLIENT_IP};
  } elsif (exists $env->{HTTP_X_REAL_IP}) {
    $dotip = $env->{HTTP_X_REAL_IP};
  } elsif (exists $env->{HTTP_X_FORWARDED_FOR}) {
    $dotip = $env->{HTTP_X_FORWARDED_FOR};
  } elsif (exists $env->{REMOTE_ADDR}) {
    $dotip = $env->{REMOTE_ADDR};
  } else {
    $dotip = &get_publicip(); # server ip
  }
  if ($dotip =~ m/^127/) {
    $dotip = &get_localip();
  }
  return $dotip;
}

sub get_publicip { # my $ip = &get_publicip();
  #y $intent = "return the client public IP from the nginX remote address variable"
  use LWP::UserAgent qw();
  my $ip;
  my $ua = LWP::UserAgent->new();
  my $url = 'http://api.safewatch.care/psgi/remote_addr.txt';
  # ip=$(curl -s https://postman-echo.com/ip?format=text)
  my $url = 'https://postman-echo.com/ip?format=text)';
  $ua->timeout(3);
  my $resp = $ua->get($url);
  if ($resp->is_success) {
    my $content = $resp->decoded_content;
    DEBUG "publicip: %s",$content;
    $ip = (split("\n",$content))[0];
  } else{
    $ip = '5.0.3.0';
  }
  return $ip;
}

sub get_localip {
    use IO::Socket::INET qw();
    # making a connectionto a.root-servers.net

    # A side-effect of making a socket connection is that our IP address
    # is available from the 'sockhost' method
    my $socket = IO::Socket::INET->new(
        Proto       => 'udp',
        PeerAddr    => '198.41.0.4', # a.root-servers.net
        PeerPort    => '53', # DNS
    );

    my $local_ip = (defined $socket) ? $socket->sockhost : '127.0.0.1';

    return $local_ip;
}

sub getNode { # Ex. my $node = &getNode()
 my $nip = shift;
 my @nodes = qw( dallas001 sydney001 );
 my $country =  &getCountry($nip);
 my $map = {
   AU => 'sydney001', 'CH' => 'dallas001', 'CZ' => 'sydney001',
   AM => 'dallas001', ZA => 'sydney001', GR => 'dallas001',
   'ww' => $nodes[rand 2], 'na' => '127.0.0.1:5000'
 };
 my $node;
 if (exists $map->{$country}) {
   if ($map->{$country} =~ m/\./) {
     $node = $map->{$country};
   } else {
     $node = $map->{$country} . '.safewatch.care';
   }
 } else {
   $node = $nodes[($nip>>8) % 2] . '.safewatch.care';
 }
 return $node;
}

sub getCountry($) {
    our $ipdb;
    intent "get the country where the user is located";
    my $nip = shift;
    DEBUG "getCountry.nip: %x",$nip;
    my $ipmin = 0x0100_00;
    my $ipmax = 0xdfff_fe;
    my $size = length($ipdb);
    if ($size == 0) {
      local *F; open F,'<',$ENV{SITE}.'/etc/ipdb.bin'; binmode(F);
      local $/ = undef;
      $ipdb = <F>;
      close F;
      $size = length($ipdb);
      INFO "loading ipdb.bin size: %d",$size;
    }
    my $p = ($nip >> 8);
    my $n = int ( ($p - $ipmin) * $size / ($ipmax - $ipmin) / 2 / 6 );
    DEBUG "p: %x",$p;
    my $a = unpack'N',substr($ipdb,$n*6,4);
    DEBUG "n0: %06x -> a: %x",$n,$a;
    while ($a > $nip) {
      $n--;
      $a = unpack'N',substr($ipdb,$n*6,4);
    }
    while ($a < $nip) {
      $n++;
      #printf "n: %d -> a:%06x\n",$n,$a;
      $a = unpack'N',substr($ipdb,$n*6,4);
      last if $n*6 > $size;
    }
    DEBUG "n: %06x -> a: %x\n",$n,$a;
    my $c = substr($ipdb,($n-1)*6,6);
    DEBUG "c: %s, %s",unpack'H8a2',$c;
    my ($a,$c) = unpack'Na2',$c;
    #returning;
    return wantarray ? ($a,$c) : $c;
}

sub getCity { # Ex. my $city = &getCity($nip);
  intent "get the city where the user is located";
  my $nip = shift;
  my $locator = $nip>>8;
  my $shard = int ($locator / 311);
  my $hash = $locator % 311;
  DEBUG "hash: %d",$hash;
  my $map = { # TBD
    90 => 'here!',
    199 => 'Lausanne, EPFL',
    252 => 'Ecublens',
    166 => 'Preverenges',
    0 => 'SomeWhere',
    undef => 'NoWhere'
  };

  my $city = $map->{$hash} || 'Ecublens, CH';
  #returning;
  return $city;
}

# -----------------------------------------------------------------------
1; # $Source: /my/perl/modules/spot.pm $
