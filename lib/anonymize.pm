#!/bin/perl

package anonymize;
use Exporter qw(import);
# Subs we export by default.
@EXPORT = qw();

# Subs we will export if asked.
#@EXPORT_OK = qw(nickname);
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_ } keys %{__PACKAGE__ . '::'};
#printf "EXPORT_OK: %s\n",join',',@EXPORT_OK;

use YAML::XS;

#use lib "$ENV{SITE}/lib";
use encode;
use kanony;

# note an anomizer is a compression algorythm that can decompress
# using a dictionary of symbol that depends on a password !

use strict;
use version;

use Encode qw(decode);
my $thereexists = decode('UTF-8','∃');

sub DEBUG {};
use IDE; our $skip = [52,117];

if (__FILE__ eq $0) {
   my $seed = pack'H32','320aa077-080c-4ab4-9803-204b7e109b49';
   my $pass = '123 password';
   my $text = "testing anonimizer from Radiant Shift by Michel Combes\n";
   my $tokenized = &tokenize_text($text);
   my $redacted = &redact_text($seed,$pass,$tokenized);
   exit $?;
}

sub tokenize_text {
  my $text = shift;
  #$text =~ s/(?<!\[)([A-Z]\w+)(?!\])/[$1]/g;
  $text =~ s/(?<!\[)([A-Z][a-z]+)(?!\])(?![^\[]*\])/[$1]/g;
  return $text;
}

sub redact_text {
  my ($seed,$pass) = (shift, $_[0]); $_[0] = 'SECRET'; delete $_[0] && shift; 
  my ($redact,undef) = &constructor($seed,$pass);
  my $text = shift;
    $text =~ s|\[([A-Z][A-Za-z/ ]+)]|$redact->($1)|ge;
    return $text;
}
sub clarify_text {
  my ($seed,$pass) = (shift, $_[0]); $_[0] = 'SECRET'; delete $_[0] && shift; 
  my $text = shift;
  my (undef,$clarify) = &constructor($seed,$pass);
  $text =~ s/\{([A-Z]+\d+)}/$clarify->($1)/ge;
return $text;
}

sub constructor {
    my ($seed, $pass, $dicts) = @_; # Assuming $dicts is passed as an argument too
    my $dicts = [qw(fnames.txt lnames.txt companies.txt emails.txt cities.txt)];
    my $nd = scalar(@$dicts);
    DEBUG "nd: %d",$nd;
    my $redact = sub {
        my $n = undef;
        my ($file,$d);
        my $orig = shift;
        for (0 .. $#$dicts) {
          $file = $dicts->[$d = $_];
          $n = lookup($file => $orig);
            DEBUG " %s: n=%s (d=%d)",$orig,$n//'undef',$d;
          last if defined $n;
        }
        return '['.$orig.']' unless defined $n;
        my $mod = scalar @{&lookup($file)};

        my $iv = int rand($mod);
        my $p = unindex($seed, $pass, $iv => $n, $mod);
        DEBUG "looked-up: %s -> %s (%s:%d) -> %s", $orig, $n//'not found', $file,$d, $p;
        my $nd = scalar(@$dicts);
        my $q = $p * $nd + $d;
        return '{REDACTED'.$q.'}';
    };
    my $clarify = sub {
      my $rname = shift;
      my $q = ($rname =~ m/(\d+)$/) ? $1 : 1401091;
      my $d = $q % $nd;
      my $file = $dicts->[$d];
      my $mod = scalar @{&lookup($file)};
      my $p = int $q / $nd;
      DEBUG " q:%s, p: %d mod:%d,  d:%d # (%s)",$q,$p,$mod,$d,$file;
      my $n = reindex($seed,$pass,$p,$mod);
      my $nname = lookup($file,$n);
      DEBUG "clarify: %s: %s -> %s -> %s",$file,$p,$n,$nname;
      return '['.$nname.']';
    };
    return ($redact,$clarify);
}

sub reindex { # Ex. $n = reindex($seed,$pass,$p,$mod);
  #EBUG "reindex(%s)",join',',map { substr(unpack('H6',$_),0,5); } @_;
  DEBUG "reindex(%s)",join',',map { my $t = (qw(H6 H6 N N N))[$_]; ($t ne 'N') ? unpack($t,$_[$_]) : $_[$_] } (0 .. $#_);
  my $mod = pop // 16381 ;
  my $seed =  shift//pack('H*','c37b4609a63a47b681411db9c08793f6');
  DEBUG "reindex.seed: %s",unpack'H*',$seed;
  
  my $q = unpack'V',khash('SHA256',$seed,@_);
  return $q % $mod; # p ⟼  n = h(p)%mod ;
}
sub unindex { # Ex. $p = unhash($seed,$pass,$iv => $n,$mod);
  # ∀ n ∈ [0,mod[ ∃ p / n = h(p)%mod i.e. p = unhash(n)
  use unhash;
  DEBUG "unindex(%s)",join',',map { my $t = (qw(H6 H6 N N N))[$_]; ($t ne 'N') ? unpack($t,$_[$_]) : $_[$_] } (0 .. $#_);
  my $mod = pop // 16381 ;
  my $seed =  shift//pack('H32','01659218-3cac-44c9-85f2-245ff9741511' =~ tr/-//dr);
  my $pass = $_[0];
  DEBUG "unindex.seed: %s # pass: %s",unpack('H*',$seed),$pass;
  DEBUG decode('UTF-8',"unindex: n=%s ∈ [0,%d[ ∃ p / n = h(p)%%%d i.e. p = unhash(n) iv=%s"), $_[2]//'undef',$mod,$mod,$_[1]//'undef';
  my $p = unhash($seed,@_,$mod);
  # verify
  my $q = unpack'V',khash('SHA256',$seed,$pass,$p);
  DEBUG "unindex: q: %u n: %d =? %d",$q,$q%$mod,$_[2];
  return $p;
}
sub khash($@) {
   use Crypt::Digest qw();
   my $alg = shift//'SHA256';
   my $data = join'',@_;
   my $msg = Crypt::Digest->new($alg) or die $!;
      $msg->add($data);
   my $hash = $msg->digest();
   return $hash;
}

# -----------------------------------------------------------------------
{ my $a = {}; # local array
  my $h = {}; # index dictionary
sub lookup {
  my $file = shift;
  if (! exists $a->{$file}) { $a->{$file} = [ loadArray($file,"\n") ]; }
  if (! exists $h->{$file}) {
     my $i = 0;
     $h->{$file} = { map { $_, $i++ } @{$a->{$file}} };
     #use YAML::XS qw(Dump);
     #printf "--- # h->{$file}: %s...\n",Dump($h->{$file});
  }
  if (@_)  {
    if (defined $_[0]) {
      use Scalar::Util::LooksLikeNumber qw(looks_like_number);
      if (looks_like_number($_[0])) {
        my $n = scalar@{$a->{$file}};
        return $a->{$file}[(shift)%$n]; # index -> name
      } else {
        DEBUG "name: h->{%s}{%s}=%s",$file,$_[0],(exists $h->{$file}{$_[0]})?$h->{$file}{$_[0]}:'do-not-exist';
        return $h->{$file}{(shift)}; # name -> index
      }
    } else {
      return wantarray?@$h->{$file}:$h->{$file}; # return the lookup table
    }
  } else {
    return wantarray?@$a->{$file}:$a->{$file}; # return the dictionary
  }
}
sub loadArray { # Ex. my @array = &loadArray($filename,"\n");
  #y $intent = "load an array from a file";
  my $file = shift;
  local *F; open F,'<',$file or die "$file: $!";
  local $/ = $_[0] // "\n";
  binmode(F) unless $file =~ m/\.txt/;
  my @lines;
  if (defined $_[0]) {
    @lines = map { chomp; $_ } <F>;
  } else {
    @lines = <F>;
  }
  close F;
  return @lines;
}
}
# -----------------------------------------------------------------------
1;
