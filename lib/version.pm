#!/usr/bin/env perl
# $Intent: act w/ Love and Kindness $

# $Author: michelc $
# $Created-On: Wed, 2023-10-31 13:04:52 $
# $Last-Modified: Fri, 2023-11-17 06:31:33 $
# .-1! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"


package version;

sub release { # Ex. my $rel = &release(time);
  #y $intent = "provide release version number with major and revision";
  my $tics = shift;
  my ($sec,$min,$hour,$mday,$mon,$yy,$wday,$yday) = (localtime($tics))[0..7];
  #my $_1yrs = 365.25 * 24 * 3600;
  my $birth = 1630501740; # D244 15:09 Sep,1 2021 - W35
  my $age = ( $tics - $birth ) / (1641392221 - $birth); # using 'late-time' (5 Jan 2022) : period = 126 days (4x/year)
  my $rweek=($yday+&fdow($tics))/7;
  my $rel_id = int($rweek) * 4;
  my $low_id = int(($wday+($hour/24)+$min/(24*60))*4/7);
  my $revision = ($rel_id + $low_id) / 100;
  my $major = int($age * 10)*10 + int($rel_id/30);
  my $rev = $low_id;
  my $version = sprintf 'v%d.%.1f.%d',int($age),int($rel_id/10)/10,$major%10+$rev;
  my $obj = {
    tics => $tics, wday => $wday, yday => $yday, birth => $birth,
    age => $age, rweek => $rweek,
    rel_id => $rel_id, low_id => $low_id,
    revision => $revision, major => $major, rev => $low_id,
    version => $version
  };
  return wantarray ? %$obj : $version;
}


sub _version { return sprintf '%.3f',(sqrt(5) + 1)/2; } # placeholder
# ----------------------------------
sub lastmod {
  my $mtime;
  local *FILE; open FILE,'<',$_[0];
  my @selected = grep m/\$Last-Modified: (.*)\s*\$/, <FILE>;
  close FILE;
  if ($selected[0] =~ m/\$Last-Modified: (.*)\s*\$/) {
    my $mdate = $1;
    my (undef,$date,$time) = split(' ',$mdate);
    my ($year,$mon,$mday) = split('-',$date);
    my ($hour,$min,$sec) = split(':',$time);
    $mtime= timelocal($sec,$min,$hour,$mday,$mon-1,$year);
    #printf STDERR "matches: %s\n",$mdate;
  } else {
    my @times = sort { $a <=> $b } (lstat($_[0]))[9,10]; # ctime,mtime
    $mtime = $times[-1]; # biggest time...
  }
  return $mtime;
}
# ----------------------------------
sub version { # get version by file
  #y $intent = "get time based version string and a content based build tag";
  #y ($atime,$mtime,$ctime) = (lstat($_[0]))[8,9,10];
  my $vtime = lastmod($_[0]);
  my $version = &rev($vtime);

  if (wantarray) {
     my $shk_raw = &get_shake(160,$_[0]);
     my $shake = unpack'H*',$shk_raw;
     my $pn = unpack('n',substr($shk_raw,-7,6)); # 40-bit
     my $build = &word($pn);
     return ($version, $build, $vtime, $shake, $pn);
  } else {
     return sprintf '%g',$version;
  }
}
# -------------------------------
sub rev { # get revision numbers
  my ($sec,$min,$hour,$mday,$mon,$yy,$wday,$yday) = (localtime($_[0]))[0..7];
  my $rweek=($yday+&fdow($_[0]))/7;
  my $rev_id = int($rweek) * 4;
  my $low_id = int(($wday+($hour/24)+$min/(24*60))*4/7);
  my $revision = ($rev_id + $low_id) / 100;
  return (wantarray) ? ($rev_id,$low_id) : $revision;
}
# -----------------------------------------
sub fdow { # get January first day of week
   my $tic = shift;
   use Time::Local qw(timelocal);
   ##     0    1     2    3    4     5     6     7
   #y ($sec,$min,$hour,$day,$mon,$year,$wday,$yday)
   my $year = (localtime($tic))[5]; my $yr4 = 1900 + $year ;
   my $first = timelocal(0,0,0,1,0,$yr4);
   our $fdow = (localtime($first))[6];
   #printf "1st: %s -> fdow: %s\n",&hdate($first),$fdow;
   return $fdow;
}
# -----------------------------------------------------------------------
sub get_shake { # use shake 256 because of ipfs' minimal length of 20Bytes
  use Crypt::Digest::SHAKE;
  my $len = shift;
  local *F; open F,$_[0] or do { warn qq{"$_[0]": $!}; return undef };
  #binmode F unless $_[0] =~ m/\.txt/;
  my $msg = Crypt::Digest::SHAKE->new(256);
  $msg->addfile(*F);
  my $digest = $msg->done(($len+7)/8);
  return $digest;
}
# -------------------------------------------------------------------
sub word { # 20^4 * 6^3 + 20^3*6^4 words (25.4bit worth of data ...)
  use Math::Int64 qw(uint64);
  # max word: pabokyrulafivacanud
  # see also: QmVMDSybz4hQnEvxc5PrKqNS7osvLHADgifaZ3PXcJh9PF
  my $n = uint64($_[0]);
  my $vo = [qw ( a e i o u y )]; # 6
  my $cs = [qw ( b c d f g h j k l m n p q r s t v w x z )]; # 20
  my $str = '';
  $str = chr(ord('a') +$n%26);
  $n /= 26;
  my $vnc = ($str =~ /[aeiouy]/) ? 1 : 0;
  while ($n > 0) {
    if ($vnc) {
      my $c = $n % 20;
      $n /= 20;
      $str .= $cs->[$c];
      $vnc = 0;
      #print "cs: $n -> $c -> $str\n";
    } else {
      my $c = $n % 6;
      $n /= 6;
      $str .= $vo->[$c];
      $vnc = 1;
      #print "vo: $n -> $c -> $str\n";
    }
  }
  return $str;
}
# -----------
sub import {
    my $caller = caller;
    no strict 'refs';
    *{$caller . '::version'} = \&version;
}

# $! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"
# -----------------------------------------------------------
1; # $Source: /ipfs/QmT3J7PWbSYfzGqDGNametGxrdaf3uteZhUWw6T7pLPBKe/version.pm $
