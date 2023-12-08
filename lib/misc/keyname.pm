#!/usr/bin/perl

package misc::keyname;
use strict;
use vars qw/$dbug/;
#ur @EXPORT = qw(firtsname shortkey);
our $qmDICT = 'QmYMr7s4pu1H9rPt727pSmLjMRWqm3B7UKNDN7tohthj2F';
# .-1! echo "our \$qmDICT = '$(cd radiant/SHIFT/cached/qmDict/ 1>/dev/null && ipfs add -w fnames.txt lnames.txt -Q)';"

#$::dbug = 1;
#$dbug = 1;
our $flist = &load_qmlist('fnames');

if (__FILE__ eq $0) {
  my $pku = shift || 'ZUPzwYQbeBRW1FBsFpFzpTH3SJVoGhC3Bwq3QT5XMBy4P';
  my $radix = scalar@$flist;
  my $fidx = &fnumber(&decode_base58f(substr($pku,1)))%$radix;
  printf "%s: %s %u\n",&firstname($pku), &shortkey($pku), $fidx;
  exit $?;
}

# -----------------------------------------------------------------------
sub findex {
   my $found;
   my $regex = qr(shift);
   for (0 .. $#$flist) {
      if ($flist->[$_] =~ $regex) { $found = $_; last }
   }
   return $found;
}
# -----------------------------------------------------------------------
sub fnumber {
  use Crypt::Digest::SHA256 qw(sha256);
  my $fprint = sha256(@_);
  my $funiq = substr($fprint,-7,6); # 6 chars (except last)
  my $quniq = unpack'Q>', pack('C2',0,0).$funiq;
  return $quniq;
}
# -----------------------------------------------------------------------
sub firstname($) {
  use Crypt::Digest::SHA256 qw(sha256);
  my $key = shift;
  my $fprint; # sha256($key); # /!\ not salted !
  if ($key =~ /^Z/) {
     $fprint = sha256(&decode_base58f(substr($key,1)));
  } elsif ($key =~ /^[0-1a-f\-]+$/) {
    my $key16 = $key; $key16 =~ y/-//d;
    $fprint = sha256('uuid:',pack'H*',$key16);
  } else {
    $fprint = sha256($key,@_);
  }
  #printf "fprint: f%s\n",unpack('H*',$fprint);
  my $funiq = substr($fprint,-7,6); # 6 chars (except last)
  my $quniq = unpack'Q>', pack('C2',0,0).$funiq;
  my $radix = scalar(@$flist);
  my $fi = $quniq % $radix;

  return $flist->[$fi];
}
# -----------------------------------------------------------------------
sub shortkey {
  if (defined $_[0]) {
    my $qm = shift;
    if ($qm =~ m/^(?:Qm|[Zmfb])/) {
      return substr($qm,0,5).'..'.substr($qm,-4);
    } else {
      return substr($qm,0,6).'..'.substr($qm,-3);
    }
  } else {
    return 'undefined';
  }
}
# -----------------------------------------------------------------------
sub load_qmlist { # my $worldlist = &load_qmlist('listname');
   #y $intent = "load a list from $DICT or an IPFS dictionary";
   my $wlist = shift;
   # ------------------------------
   our $wordlist ||= [];
   my $wl = scalar @$wordlist;
   if ($wl < 1) {
      my $buf;
      my $DICT = $ENV{DICT} || '.';
      if (-d $DICT && -e "$DICT/$wlist.txt") {
        printf " using: %s\n","$DICT/$wlist.txt" if $dbug;
        $buf = &get_file("$DICT/$wlist.txt");
      } else {
        $buf = &get_ipfs_content("/ipfs/$qmDICT/$wlist.txt");
        if (-w "$DICT/$wlist.txt") { 
          &write_file("$DICT/$wlist.txt",$buf);
        }
      }
      if (ref($buf) eq 'HASH' || $buf eq '') {
        return undef;
      }
      @$wordlist = grep !/^#/, split("\n",$buf);
      $wl = scalar @$wordlist;
      printf "wlist: %s=%uw\n",$wlist,$wl if $dbug;
   }
  return $wordlist;
}
# -----------------------------------------------------------------------
sub get_file { # my $buf = &get_file($filename);
 #y $intent = "read a file";
 local *F;
 local $/ = undef;
 open F,'<',$_[0];
 my $buf = <F>;
 close F;
 return $buf;
}
# -----------------------------------------------------------------------
sub get_ipfs_content { # my $content = &get_ipfs_content($ipath);
  #y $intent = "retrieve data from an ipfs path";
  # TODO make it cacheable
  my $ipath=shift;
  use LWP::UserAgent qw();
  my ($gwhost,$gwport) = &get_gwhostport();
  my $proto = ($gwport == 443) ? 'https' : 'http';
  my $url = sprintf'%s://%s:%s%s',$proto,$gwhost,$gwport,$ipath;
  printf "url: %s\n",$url if $::dbug;
  my $ua = LWP::UserAgent->new();
  my $resp = $ua->get($url);
  if ($resp->is_success) {
    my $content = $resp->decoded_content;
    return $content;
  } else {
    return undef;
  }
}
# -----------------------------------------------------------------------
sub get_gwhostport { # my ($gw,$port) = &get_gwhostport();
  #y $intent = "get ipfs gateway information";
  our($gwhost,$gwport);
  if (defined $gwport) { return ($gwhost,$gwport); }
  my $IPFS_PATH = $ENV{IPFS_PATH} || $ENV{HOME}.'/.ipfs';
  my $conff = $IPFS_PATH . '/config';
  printf "\/\/ config: %s\n",$conff if $dbug;
  local *CFG; open CFG,'<',$conff or warn $!;
  local $/ = undef; my $buf = <CFG>; close CFG;
  use JSON::XS qw(decode_json);
  my $json = decode_json($buf);
  my $gwaddr = $json->{Addresses}{Gateway};
     (undef,undef,$gwhost,undef,$gwport) = split'/',$gwaddr,5;
      $gwhost = '127.0.0.1' if ($gwhost eq '0.0.0.0');
  my $url = sprintf'http://%s:%s/ipfs/zz38RTafUtxY',$gwhost,$gwport;
  printf "try: http://%s:%s/ipfs/zz38RTafUtxY\n",$gwhost,$gwport if $dbug;
  my $ua = LWP::UserAgent->new();
  my $resp = $ua->get($url);
  if ($resp->is_success) {
    return ($gwhost,$gwport);
  } else { #do a second attempt on 0:8080
    my $ua = LWP::UserAgent->new();
    $gwhost = 'localhost';
    $gwport = 8080;
    my $url = sprintf'http://%s:%s/ipfs/zz38RTafUtxY',$gwhost,$gwport;
    printf "try-again: http://%s:%s/ipfs/zz38RTafUtxY\n",$gwhost,$gwport if $dbug;
    $resp = $ua->get($url);
    if ($resp->is_success) {
      return ($gwhost,$gwport);
    } else {
      print STDERR 'info: using ipfs.safewatch.care:443',"\n";
      $gwhost = undef;
      $gwport = undef;
      return ('ipfs.safewatch.care',443);
    }
  }
}
# -----------------------------------------------------------------------
sub write_file { # my $status = &write_file($filename,$data);
  #y $intent = "write data to a file";
  my $file = shift;
  printf "file: %s, (%dB)\n",$file,length($_[0]);
  my $dirname = substr($file,0,rindex($file,'/'));
  &mkdirp($dirname) unless -d $dirname;
  local *F; open F,'>',$file or die $!; # TBD use semaphore
  binmode(F) unless $file =~ m/\.txt/;
  print F $_[0];
  close F;
  return $?;
}
sub mkdirp { # &mkdirp($dirname);
  #y $intent = "implement a mkdir -p"
  my @fp = ();
  for my $p (split('/',$_[0])) {
    push @fp,$p;
    my $fp = join'/',@fp;
    #printf "fp: %s\n",$fp;
    mkdir $fp unless -d $fp;
  }
  return $?;
}
# -----------------------------------------------------------------------
sub decode_base58f { # my $data = &decode_base58f('Z58fstring');
  #y $intent = "decode data from flickr-base58";
  use Math::BigInt;
  use Encode::Base58::BigInt qw();
  my $s = $_[0];
  #$s =~ tr/A-HJ-NP-Za-km-zIO0l/a-km-zA-HJ-NP-ZiooL/; # btc
  $s =~ y/0-9A-Za-z//dc;
  $s =~ tr/IO0l/iooL/; # forbidden chars
  my $bint = Encode::Base58::BigInt::decode_base58($s);
  my $bin = Math::BigInt->new($bint)->as_bytes();
  return $bin;
}
# -----------------------------------------------------------------------
sub import {
    my $caller = caller;
    my $pkg = shift;
    no strict 'refs';
    for (@_) {
     #print "${pkg}::$_\n";
      *{$caller . "::$_"} = \&{$_};
    }
}
# -----------------------------------------------------------------------
# .+2! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"
# -----------------------------------------------------------------------
1; # $Source: $
