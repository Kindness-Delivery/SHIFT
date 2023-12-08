#!/usr/bin/perl

#
# Intent:
#  re-usable routines ...
#
# Note:
#   This work has been done during my own time at Doctor I·T
# 
# -- Copyright drit, 2021 --
#BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }
#
package misc;
use Exporter qw(import);
#require Exporter;
#@ISA = qw(Exporter);
# Subs we export by default.
@EXPORT = qw();
# Subs we will export if asked.
#@EXPORT_OK = qw(nickname);
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};
push @EXPORT_OK, qw($inonce);

use strict;
use version qw(version);

# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');

printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------
our $inonce = unpack 'Q',&decode_base32a('Initial nonce!');
printf "inonce: %u\n",$inonce if $dbug;

our $lcg = $inonce;

use Log::Trace;
#import Log::Trace;
sub TRACE_HERE;
sub TRACEF;
sub TEACE;

# -----------------------------------------------------------------------
# namespace id: 13 char of base36(sha256)
# 13 is chosen to garantie uniqness
# over a population of 2^64 nodes
# ----------------------------------
sub get_nid { # Ex. my $nid = &get_nid($token);
 my $len = ($#_ > 0) ? pop : 13;
 my ($pk,$name,$typ) = split('\$',shift);
 use encode qw(encode_base36);
 TRACE_HERE {Level=>8};
 my $sha2 = &khash('SHA256',$pk,@_);
 my $ns36 = &encode_base36($sha2); # /!\ slow
 my $nid = lc substr($ns36,0,$len);
 if (wantarray) {
   use MIME::Base64 qw(encode_base64);
   my $ns64 = &encode_base64($sha2);
      $ns64 =~ tr,+/,,d;
   my $shard = lc substr($ns64,0,$len); # b36-equivalant: lc(base64)
   my $sha16 = unpack('H*',$sha2);
   return ( nid => $nid, pku => $pk, sha => $sha16, shard => $shard );
 } else {
   return $nid;
 }
}
# -----------------------------------------------------------------------
sub get_shard { # Ex. my $shard = &get_shard($pku);
 #y $itent = "get a simple alphanumeric shard";
 my $len = ($#_ > 0) ? pop : 3;
 my $name = join'',@_;
 #$name =~ tr/a-zA-Z0-9/./cs;
 $name =~ tr/a-zA-Z0-9//dc;
 return lc substr($name,-$len-1,$len);
}
# -----------------------------------------------------------------------
sub get_shard16 {
 #y $itent = "get hexadecimal shard";
 my $len = ($#_ > 0) ? pop : 16;
 my $hash = &khash('SHA256',@_);
 my $shard = unpack"H$len",$hash;
 return $shard;
}
# -----------------------------------------------------------------------
sub get_shard36 {
 use MIME::Base64 qw(encode_base64);
 my $len = ($#_ > 0) ? pop : 13;
 my $hash = &khash('SHA256',@_);
 my $ns64 = encode_base64($hash,'');
    $ns64 =~ tr,+/,,d;
 my $shard = lc substr($ns64,0,$len); # b36-equivalant: lc(base64)
 return $shard;
}
# -----------------------------------------------------------------------
sub lcg { # x = (a * x + c ) % m;
   #y $m = (1<<31)-1); # prime 2147483647
   #y $a = int($phi * (1<<32));
   # a = 2654435769 = 3 × 7 × 23 × 89 × 683
   # largest 32b prime: 4294967291
   # prime before 10B : 9999999967
   return $lcg = ($lcg * 2654435769 ) % 4294967291;

   # primes:
   # (1<<61)-1 = 2305843009213693951
   #             2305843009213693921
   # (sqrt(5) + 1) * 2^62
   #$lcg = ($lcg * 14923729446516375050 ) % 18446744073709551557
   # largest 64b prime: 18446744073709551557
}
sub lfsr32 {
    our $lfsr = shift if @_;
    # taps: 32 31 29 1; feedback polynomial: x^32 + x^31 + x^29 + x + 1
    $lfsr = ($lfsr >> 1) ^ (-(int($lfsr) & 1) & 0xD0000001);
}
sub lfsr56 {
    our $lfsr = shift if @_;
    $lfsr = ($lfsr >> 1) ^ (-(int($lfsr) & 1) & 0x80000000600003);

}
# -----------------------------------------------------------------------
sub get_uid { # Ex. my $uid = &get_uid($name,$salt);
 #y $intent = "pseudo anoymized a name";
 my $uid;
 my $salt;
 my $legacy = 1; # use option to use new uid
 if (ref($_[-1]) eq 'HASH') {
   my $args = { pop };
   $salt = pack'N',$args->{salt} || $$;
   $legacy = (exists $args->{legacy}) ? $args->{legacy} : 0;
 } else {
   $salt = pack'N',pop;
 }
 printf "get_uid.salt: f%08x (%dc)\n",unpack('N',$salt),length($salt);
 use encode qw(varint encode_base36);
 my $sha2 = &khash('SHA256',@_,$salt,varint(length($_[0])));
 if ($legacy) {
    use encode qw(encode_base36);
    $uid = &encode_base36($salt.substr($sha2,-9,8));
 } else {
    use MIME::Base64 qw(encode_base64);
    $uid = &encode_base64($salt.substr($sha2,-9,8),'');
    $uid =~ tr,+/,,d;
 }
 return lc $uid;
}

# ---------------------------------------
sub gettics { # my $ticns = &gettics();
  #y $intent = "get high resolution time in second since epoch";
  use Time::HiRes qw( clock_gettime CLOCK_REALTIME);
  # Read the POSIX high resolution timer.
  my $highres = clock_gettime(CLOCK_REALTIME);
  #y $tics = clock_gettime(&Time::HiRes::CLOCK_MONOTONIC);

  my $caller = (caller(1))[3]; $caller =~ s/.*:://;
  TRACEF "%s.tics: %s\n",$caller,($0 =~ m/\.t$/) ? 1634239703.881 : $highres;
  return int(($highres + 0.49999) * 1000_000_000);
}
# -----------------------------------------------------------------------
sub get_salt { # Ex. my $salt = & get_salt($uid);
  use encode qw(varint decode_base36);
  my $data = &decode_base36($_[0]);
  my ($salt,$hash) = unpack'N2',$data;
  return wantarray ? ($salt,$hash) : $salt;
}
# -----------------------------------------------------------------------
sub get_username { # Ex. my $username = &get_username($name);
  #y $intent = "extract username from name";
  my $name = shift;
  return undef unless $name;
  $name =~ tr /a-zA-Z0-9/ /cs;
  my ($fn,@names) = split(/ +/,$name);
  #printf "debug.name: %s\n",$name;
  #printf "debug.fn: %s\n",$fn;
  #printf "debug.names: %s\n",join(',',@names);
  my $user = lc( (@names) ? sprintf('%s%s',$fn,substr($names[-1],0,1)) : $fn );
  return $user;
}
# -----------------------------------------------------------------------
sub get_spotid {
   my ($ts,$ip) = (shift,shift);
   my $spot = pack('N',$ts).pack'C4',split('\.',$ip);
   my $qspot = unpack'Q',$spot;
   return $qspot;
}
# -----------------------------------------------------------------------
sub getuuid {
  use Crypt::URandom qw();
  my $uuid;
  if (@_) {
    my $salt = (@_[1]) ? pack'N',pop : Crypt::URandom::urandom(4);
    my $hash = &khash('SHA256','secret',@_,length($_[0]),$salt);
    $uuid = $salt.substr($hash,-17,12);
  } else {
    $uuid = Crypt::URandom::urandom(16);
  }
  vec( $uuid, 13, 4 ) = 0x4; # set UUID version
  vec( $uuid, 35, 2 ) = 0x2; # set UUID variant
  return join '-', unpack'H8H4H4H4H12', $uuid;
}
# -----------------------------------------------------------------------
sub _getuuid {
	my $uuid = '';
	for ( 1 .. 4 ) {
		$uuid .= pack 'N', int(rand(2 ** 32)); # /!\ unsecure
	}
  # killing 6 bits !
	substr $uuid, 6, 1, chr( ord( substr( $uuid, 6, 1 ) ) & 0x0f | 0x40 );
	substr $uuid, 8, 1, chr( ord( substr( $uuid, 8, 1 ) ) & 0x3f | 0x80 );

	return join '-',
		map { unpack 'H*', $_ }
		map { substr $uuid, 0, $_, '' } ( 4, 2, 2, 2, 6 );
}
# -----------------------------------------------------------------------
sub getv3uuid {
  use Data::UUID;
  my $pku = shift;
  my $ug = Data::UUID->new;
  my $url = sprintf'https://api.safewatch.care/api/v0/public/name?pubkey=%s',$pku;
  #my $md5 = khash('MD5',$url);
  #my $sha1 = khash('SHA1',$url);
  my $uuidv3 = $ug->create_from_name_str(NameSpace_URL, "$url");
  return $uuidv3
}
# -----------------------------------------------------------------------
sub getv4uuid {
  use Crypt::URandom qw();
  my $uuid = Crypt::URandom::urandom(16);
  vec( $uuid, 13, 4 ) = 0x4; # set UUID version
  vec( $uuid, 35, 2 ) = 0x2; # set UUID variant
  return join '-', unpack'H8H4H4H4H12', $uuid;
}
# -----------------------------------------------------------------------
sub _getv4uuid {
  # Version 4 - random - UUID: xxxxxxxx-xxxx-4xxx-Yxxx-xxxxxxxxxxxx
  # where x is any hexadecimal digit and Y is one of 8, 9, A, B (1000, 1001, 1010, 1011)
  # e.g. f47ac10b-58cc-4372-a567-0e02b2c3d479
  use Crypt::URandom qw();
  my $raw = Crypt::URandom::urandom(16);
  #                    0 1 2 3 4 5 6 7 8 9 0
  #                   xxxxxxxxxxxx4xxxYxxxxxxxxxxxxxxx
  $raw &= pack("H*", "FFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFF");
  $raw |= pack("H*", "00000000000040000000000000000000");
  $raw &= pack("H*", "FFFFFFFFFFFFFFFF3FFFFFFFFFFFFFFF"); # 0x3 == 0011b
  $raw |= pack("H*", "00000000000000008000000000000000"); # 0x8 == 1000b
  my $hex = unpack("H*", $raw);
  $hex =~ s/^(.{8})(.{4})(.{4})(.{4})(.{12}).*$/$1-$2-$3-$4-$5/;
  return $hex;
}
# -----------------------------------------------------------------------
sub getv5uuid {
  use UUID::Tiny qw(UUID_V5 UUID_NS_URL create_uuid_as_string);
  my $pku = shift;
  my $url = sprintf'https://api.safewatch.care/api/v0/public/name?pubkey=%s',$pku;
  my $v5uuid = create_uuid_as_string(UUID_V5, UUID_NS_URL, $url);
  return $v5uuid;
}
# -----------------------------------------------------------------------
sub botword {
  use encode qw(decode_base58f);
  my $key = shift;
  my $bin = decode_base58f(substr($key,1));
  my $digest = &keyw($bin);
  return $digest;
}
# -----------------------------------------------------------------------
sub kwdigest {
  if (! defined $_[0] ) { return &keyw(khash('SHA256','')); }
  my $hash;
  my $ref = ref($_[0]);
  #printf "kwdigest: ref(_[0])=%s\n",$ref;
  if ($ref eq 'HASH') {
     my $obj = { %{$_[0]} }; # copy object !
     delete $obj->{meta} if (exists $obj->{meta});
     $hash = khash('SHA256',yamlify($obj));
  } elsif ($ref eq 'ARRAY') {
     my $obj = [ @{$_[0]} ];
     $hash = khash('SHA256',yamlify($obj));
  } else {
     $hash = khash('SHA256',@_);
  }
  return &keyw($hash);
}
# -----------------------------------------------------------------------
sub keyw { # get a keyword from a hash (using 8 Bytes)
  my $hash=shift;
  my $o = (length($hash) > 11) ? -11 : -8;
  my $n = unpack'N',substr($hash,-$o,8);
  my $kw = &word($n);
  return $kw;
}
# -----------------------------------------------------------------------
sub decode_base32a {
  use MIME::Base32 qw();
  my $s = shift;
     $s =~ tr [01v2_\-+/', :.!&$*%] [OIVZUMPSQCSCDXNSxP];
     $s =~ y/ybndrfg8ejkmcpqxotluwisza345h769/A-Z2-7/;
  return &MIME::Base32::decode_base32($s);
}
# -----------------------------------------------------------------------
# max word: pabokyrulafivacanud QmVMDSybz4hQnEvxc5PrKqNS7osvLHADgifaZ3PXcJh9PF
sub word { # 20^4 * 6^3 + 20^3*6^4 words (25.4bit worth of data ...)
  use Math::Int64 qw(uint64);
  my $n = uint64($_[0]);
  my $vo = [qw ( a e i o u y )]; # 6
  my $sc = [qw ( b mb mp c cc ch d f g gh h j k l ll m n nc nd ng nk ns nt nx p ph pp q r s sh t st v w x z )]; # 20
  my $mc = [qw ( h bl br ck cl cr chr dr ff fl fr gr jr kr kl mm mn mw nn nf nj nl nq nr nv nw nz pl pr qr sl sr shr tr th thr vl vr wr zr )]; # 20
  my $cs = [@$sc,@$mc];
  my $nc = scalar(@$cs);
  my $nm = scalar(@$mc);
  my $ne = scalar(@$sc);

  my $str = '';
  if ($n < 2) {
    return $n ? 'b' : 'a';
  }
  my $cnv = ($n % 2) ? 1 : 0;
  $n /= 2;
  while ($n > 0) {
    if ($cnv) {
      my $c = $n % $nc;
      $n /= $nc;
      $str .= $cs->[$c];
      $cnv = 0;
      #print "cs: $n -> $c -> $str\n";
    } else {
      my $c = $n % 6;
      $n /= 6;
      $str .= $vo->[$c];
      $cnv = 1;
      #print "vo: $n -> $c -> $str\n";
    }
  }
  return $str;
}
# -----------------------------------------------------------------------
sub canon {
  my $word = shift;
  my @word = split'',$word;
  sub randomly { my $r = rand(1); $r<0.5 ? -1 : $r>0.5 ? 1 : 0; }
  my $canon = join'',$word[0],( sort randomly @word[1 .. $#word-1]),$word[-1];
  return $canon;
}
# -----------------------------------------------------------------------
sub indent {
  my $i = shift;
  my $buf = join'',@_;
  my $pad = ' 'x$i;
  $buf =~ s/\n/\n$pad/g;
  return $pad.$buf;
}
# -----------------------------------------------------------------------
sub nonl {
  my $buf = shift;
  $buf =~ s/\\n/\\\\n/g;
  $buf =~ s/\n/\\n/g;
  if (defined $_[1]) {
   $buf = substr($buf,$_[0],$_[1]);
  }
  return $buf;
}
# ------------------------------
sub nl {
  my $buf = $_[0];
  $buf =~ s/\\\\n/{55799-ds}/g;
  $buf =~ s/\\n/\n/g;
  $buf =~ s/{55799-ds}/\\n/g;
  return $buf;
}
# -----------------------------------------------------------------------
sub args { # Ex. my ($addr,$pku,$seed,$auth) = &args([qw(addr pku seed auth)],@_);
   return @_ if (ref($_[0]) ne 'ARRAY');
   $pargs = shift;
   my $arg = { @_ };
   my $args = [];
   foreach my $p (@$pargs) {
     push @$args, $arg->{$p} 
   }
   return wantarray ? (@$args,$args) : $args;
}
# -----------------------------------------------------------------------
sub binarify {
   use YAML::XS qw(Dump);
   use encode qw(decode_base58f);
   my $obj = shift;
   my $type = pop;
   if ($type eq 'link') {
     my $data = decode_base58f(substr($obj->{bkaddr},1));
     $data .= decode_base58f(substr($obj->{bkprev},1));
     $data .= pack'Q',($obj->{nonce}||$inonce); # note: initial nonce is included in the data itself (keyed hash !)
     return ($data,$obj->{pow}||$obj->{nonce});
   } else {
      my $nonce = $obj->{pow}||$obj->{nonce};
      #$obj->{pow} = 0x0102_0304_0506_0708; # yet no work done
      my $yml = Dump($obj);
     return ($yml,$nonce);
   }
}
# -----------------------------------------------------------------------
sub yamlify {
   use YAML::XS qw(Dump);
   my $obj = shift;
   my $yml = Dump($obj);
   return $yml;
}
# -----------------------------------------------------------------------
sub jsonify {
   use JSON::XS qw();
   my $obj = shift;
   #y $json = encode_json( $obj ); # /!\ keys are not sorted !
   my $json = JSON::XS->new->allow_blessed(1)->canonical;
   # canonical : sort keys
   # blessed : { %$env } for Plack
   return $json->encode($obj);
}
# -----------------------------------------------------------------------
sub objectify {
  my $content = shift;
  use JSON::XS qw(decode_json);
  if ($content =~ m/\}\n\{/m) { # nd-json format (stream)
    my $resp = [ map { &decode_json($_) } split("\n",$content) ] ;
    return $resp; 
  } elsif ($content =~ m/^{/ || $content =~ m/^\[/) { # plain json]}
    #printf "[DBUG] Content: %s\n",$content;
    my $resp = &decode_json($content);
    return $resp;
  } elsif ($content =~ m/^--- /) { # /!\ need the trailing space
    use YAML::XS qw(Load);
    my $resp = Load($content);
    return $resp;
  } else {
    #use LOG qw(debug);
    TRACEF {Level=>0}, "info: %s...\n",substr($content,0,24);
    return $content;
  }
}
# -----------------------------------------------------------------------
sub deobjectify {
  my $addr = shift;
  my $object = shift;
  if (ref($object) ne '') {
     my $ext = substr($addr,rindex($addr,'.')+1);
     if ($ext eq 'json') {
        use misc qw(jsonify);
        $data = jsonify($object);
     } else {
        use YAML::XS qw(Dump);
        local $YAML::XS::QuoteNumericStrings = 0;
        $data = Dump($object);
        $data =~ s/^---/--- # $addr/;
     }
  } else {
     $data = $object;
  }
  return $data;
}
# -----------------------------------------------------------------------
sub khash { # keyed hash
   use Crypt::Digest qw();
   my $alg = shift || 'SHA256';
   my $data = join'',@_; delete $_[0];
   my $msg = Crypt::Digest->new($alg) or die $!;
      $msg->add($data);
   my $hash = $msg->digest();
   return $hash;
}
# -----------------------------------------------------------------------
sub khmac($$@) { # Ex. my $kmac = &khmac($algo,$secret,$nonce,$message);
  #y $intent = qq'to compute a keyed hash message authentication code';
  use Crypt::Mac::HMAC qw();
  my $algo = shift;
  my $secret = shift;
  #printf "khmac.secret: f%s\n",unpack'H*',$secret;
  my $digest = Crypt::Mac::HMAC->new($algo,$secret); undef $secret;
     $digest->add(join'',@_);
  return $digest->mac;
}
# -----------------------------------------------------------------------
sub get_khash { # keyed hash of a file
   use Crypt::Digest qw();
   my $alg = shift;
   my $file = pop;
   my $data = join'',@_;
   local *F; open F,$file or do { warn qq{"$file": $!}; return undef };
   #binmode F unless $file =~ m/\.txt/;
   my $msg = Crypt::Digest::new($alg);
   $msg->add($data);
   $msg->addfile(*F);
   my $hash = $msg->digest();
   return $hash;
}
# -----------------------------------------------------------------------
sub get_url {
   my $url = shift;
   use LWP::Simple qw(get);
   my $content = get $url;
   warn "Couldn't get $url" unless defined $content;
   return $content;
}
# -----------------------------------------------------------------------
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -n -w % -Q)/%:t \$"
1; # $Source: /ipfs/QmVGSs9yREarAoVEYjn295XSTvrET8pepUDpKdUdsM7Qsc/misc.pm $
