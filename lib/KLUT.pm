#!/bin/perl
BEGIN { if (__FILE__ eq $0 && defined $ENV{QMLIB} && -d "$ENV{XDG_CACHE_HOME}/qmlib/$ENV{QMLIB}") { require lib; lib->import("$ENV{XDG_CACHE_HOME}/qmlib/$ENV{QMLIB}"); } }
package KLUT;
our @EXPORT_OK = qw(KLUT setKLUT getKLUT);

our $klut;


# $Intent: kindly provide (sharded) and encrypted LUT $


use encode;
use env;
use YAML::XS qw(Dump);

no warnings 'redefine';
sub SECURE{};
sub DEBUG{};
use IDE; our$skip = [41,54..67,72,93,90,100,111];

my $tk509 = encode_base32e(substr(KH(decode_uuid('3f275e4a-be5f-4de3-bf59-c3cbb9be6458'),'shard','/509'),12,16)) // '08F6RHYKIB4S7SQVBQ0T4BN66X';

if (! defined $klut) {
   use misc::ipfs qw(ipfsread);
   # ipfs files write --truncate /etc/klut/bootsecrets.yml ~/clear/bootsecrets.yml
   # ipfs files write --truncate /etc/klut/identities.yml ~/drafts/etc/klut/identities.yml
   $klut = ipfsread(arg=>'/etc/klut.yml');
   if (ref $klut eq 'HASH' && $klut->{Type} eq 'error') {
      $klut = { 'error' => { mh => $klut } };
   }
   #DEBUG "--- # klut: %s...",Dump($klut);
}


sub KLUT { # Ex. my $access = KLUT($seedk,$addr,[secret]);
   # y $intent = "provide a secure distribute key-value store"
   use kanony;
   use XKH qw(KH XOR);
   DEBUG "klut.args: %s",join', ',map { substr(unpack('H*',$_),0,5); } @_;
   my $seedk = shift || decode_uuid('551162a7-e18c-41a5-8308-e59199baa738');
   DEBUG "klut.seedk64: %s",encode_base64($seedk);
   my $seedk64 = encode_base64($seedk);
      $seedk58 = &ENV(KLUT_ENCRYPTION_SEED => $seedk64, 1686283);
      $seedk = decode_mbase($seedk58);
   # DEBUG "seedk58: %s # %s %s  %s",$seedk58,kaname($seedk);
   # DEBUG "seedk16: %s",encode_uuid(decode_mbase58($seedk58));
   my $addr = shift;

   my $cipher = decode_uuid('12e510c6-0b43-41a3-b3fd-af9bda91c7e3');
   my $key = KH($seedk,'klut',$addr); # KLUT encryption key
   SECURE "klut.key: %s",$key;
   my $hash = KH($seedk,'token',$addr); # KLUT record location hash
   my $shard = unpack'H5',substr($hash,-4,3);
   DEBUG "klut.hash: %s # %s",encode_base64($hash),$shard;
   $klut->{$shard} = loadKLUT($shard) if (! exists $klut->{$shard});
   my $token = encode_base32e(substr($hash,12,16)); # hash supposed to be 32B
   DEBUG "klut.shard %s",$shard;
   DEBUG "klut.token: %s",$token;
   
   if (@_)  { # write
      use pwned qw(pwname);
      my $access = pop || decode_uuid('880e71f9-ab24-4ade-b4e4-53314999c92d');
      $cipher = encode_uuid( XOR($access,$key) );
      $klut->{$shard}{$token} = $cipher;
      DEBUG "klut.addr: %s",$addr;
      DEBUG "klut.access: %s # %s %s  %s",encode_uuid($access),kaname($access);
      DEBUG "klut.key: %s # %s  %s %s",encode_uuid($key),pwname($key);
      DEBUG "saveKLUT(%s): %s => %s",$shard,$token,$cipher;
      my $resp = saveKLUT($shard); # /!\ locally saved on ipfs node
      return $access;
   } elsif (exists $klut->{$shard}) {
      DEBUG "klut.addr: %s",$addr;
      if (exists $klut->{$shard}{$token}) {
         $cipher = $klut->{$shard}{$token};
      } else {
         $cipher = $klut->{$shard}{$tk509} || '4b03c389-6817-4a42-9fa7-7873dd00bc80';
      }
   } else {
      my $default = unpack'H5',substr(KH($seedk,'shard','default'),-4,3);
      $cipher = $klut->{$default}{$tk509} || '3349d37b-bc68-44ff-ad7c-00ffd2843aa3';
   }
   DEBUG "klut.%s: %s: %s",$shard,$addr,$cipher;
   my $access = XOR(decode_uuid($cipher),$key);
   return $access;
}

sub getKLUT {
   use XKH qw(KH XOR);
   my $seedk64 = &ENV(KLUT_ENCRYPTION_SEED => '551162a7-e18c-41a5-8308-e59199baa738');
   my $seedk = decode_mbase($seed64);
   my $addr = shift;
   my $shard = unpack'H5',substr(KH($seedk,'shard',$addr),-4,3);
   if (! exists $klut->{$shard}) {
      $klut->{$shard} = loadKLUT($shard);
   }
   my $cipher = decode_mbase($klut->{$shard}{$addr});
   my $key = KH($seedk,'klut',$addr);
   my $access = XOR($cipher,$key);
   return $access;
}
sub setKLUT {
   use XKH qw(KH XOR);
   my $seedk64 = &ENV(KLUT_ENCRYPTION_SEED => '551162a7-e18c-41a5-8308-e59199baa738');
   my ($addr,$access) = (shift,pop);
   my $seedk = decode_mbase($seed64);
   my $hash = KH($seedk,'shard',$addr);
   my $shard = unpack'H5',substr($hash,-4,3);
   my $token = encode_base32e(substr($hash,12,16));
   if (! exists $klut->{$shard}) {
     $klut->{$shard} = loadKLUT($shard);
   }
   my $key = KH($seedk,'klut',$addr);
   my $cipher = XOR($access,$key);
   $klut->{$shard}{$token} = encode_base64($cipher);
   my $resp = saveKLUT($shard); # /!\ locally saved on ipfs node
   return $cipher;
}

sub loadKLUT {
  use misc::ipfs qw(ipfsread);
  my $shard = shift;
  my $addr = sprintf '/etc/klut/%s.yml',$shard; 
   $resp = ipfsread(arg=>$addr);
   if (ref $resp eq 'HASH' && $resp->{Type} eq 'error') {
      DEBUG "--- # %s: %s...",$addr,Dump($resp);
      return { 'error' => { resp => $resp }, $tk509 => '00491688-8dd7-410f-bf58-c21ae3028760' };
   } else {
      return $resp;
   }
}
sub saveKLUT { # Ex. my $resp = saveKLUT($shard)
  use misc::ipfs qw(ipfswrite);
  my $shard = shift;
  my $addr = sprintf '/etc/klut/%s.yml',$shard; 
  # TODO need semaphore !
  delete $klut->{$shard}{error} if exists $klut->{$shard}{error};
  my $resp = ipfswrite(arg=>$addr, Content => $klut->{$shard});
  DEBUG "--- # %s: %s...",$addr,Dump($klut->{$shard});
  # ipfs files read /etc/klut/identities.yml
  return $resp;
}
      

sub import {
    my $caller = caller;
    no strict 'refs';
    *{$caller."::klut"} = \$klut;
    for (@EXPORT) {
       *{$caller."::$_"} = \&{$_};
    }
    for (@EXPORT_OK) {
      if (exists ${$caller.'::'}{$_}) {
       *{$caller."::$_"} = \&{$_};
      }
    }
    for (@_) {
       *{$caller."::$_"} = \&{$_};
    }
}
1;
