#!/bin/perl


package register;
use Exporter qw(import);
our @EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};


use kanony;
use pwned qw(pwname);
use encode;
use misc;
use misc::date;
sub DEBUG{};
sub SECURE{};
use IDE;

sub register {
   use KLUT;
   use XKH qw(KH DH KM);
   my ($name,$passcode,$mnemo,$args) = args([qw(name passcode mnemo)],@_);
   my $regkey = KDF($name,$passcode,$mnemo); # /!\ make sure $name + $mnemo are unique
   my $regkey64  = encode_base64($regkey);
   DEBUG "register.regkey64: %s # %s  %s %s",$regkey64,&pwname($regkey);

   my $reginfo = { getRegId($name,$passcode,$mnemo, key => $regkey) };
   my $regid = decode_uuid($reginfo->{reguuid});
   # get pku to get session key...
   my $pku58 = $args->{pubkey} || 'ZV4Ex2PY371cXKGw12ZBsyXcUbaY1UziDVroGaVn6TgHd' || 'Z223CLvvTBagprnX1aZq2AuR5cVVd7VkfbfnnoBy5HAr3G';
   my $pku = decode_mbase58($pku58);
   


   my $weekly = int $tofu/3600/24/7 * OPHI;
   my $sessionid = $args->{sessionid} || $weekly;

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', 1686197);
   my $seedr = decode_mbase($seedr64);

   DEBUG "pku: %s",$args->{pubkey};
   my $seedk = KM($seedr,'seed',$pku); # to protect KLUT
   my $access = KLUT($seedk,'regid:'.$regkey64,$regid);
   return $access;
   
}
sub getRegistry {
   my ($name,$passcode,$mnemo,$args) = args([qw(name passcode mnemo)],@_);
   my $regkey = KDF($name,$passcode,$mnemo); # /!\ make sure $name + $mnemo are unique
   my $regkey64  = encode_base64($regkey);

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', 1686197);
   my $seedr = decode_mbase($seedr64);
   DEBUG "pku: %s",$args->{pubkey};
   my $seedk = KM($seedr,'seed',decode_mbase58($args->{pubkey})); # to protect KLUT

   my $regid = KLUT($seedk,'regid:'.$regkey64);
   use XKH qw(XOR);
   my $uuid = XOR($regid,$regkey);
   DEBUG "uuid: %s # %s %s  %s",encode_uuid($uuid),kaname($uuid);
   my $pki = pubKeyOf($uuid);
   DEBUG "pki: %s # %s %s  %s",encode_mbase58($pki),kaname($pki);

   return $regid;
}
sub getRegKey { # Ex. my $regkey = getRegId($name,$secret,$URI, access => $access);
    use KDF;
    use misc qw(args);
    my ($name,$secret,$mnemo,$args) = args([qw(name secret mnemo)],@_);
    my $regkey = KDF($name,$secret,$mnemo); # /!\ make sure $name + $mnemo are unique
    my $regkey64  = encode_base64($regkey);
    DEBUG "regKey64: %s # %s  %s %s for %s %s",$regkey64,pwname($regkey),$name,$mnemo;
    return $regkey;
}

sub getRegId { # Ex. my $reginfo = getRegId($name,$secret,$URI);
    use misc qw(args);
    use XKH qw(KH);
    my ($name,$secret,$mnemo,$args) = args([qw(name secret mnemo)],@_);
    # ----------------------------------------------------
    # --- spot ---
    my $seedr58 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', 1686197);
    DEBUG "seedr: %s",$seedr58;
    my $seedr = decode_mbase($seedr58);
    my $spotkey64 = encode_base64(substr(KH($seedr,'spot',$name,$mnemo),-17,16));
    my $spot = &getSpotByKey($spotkey64,\%ENV); # space & time
    # ------------
    my $regid = KH($seedr,$name,$spot); # <--- 
    my $reguid = substr($regid,-17,16);
    my $reguuid = encode_uuid($reguid);
    DEBUG "regid: %s # %s %s  %s",encode_base64($regid),kaname($regid); 
    DEBUG "reguuid: %s # %s",$reguuid,(kaname($reguid))[1]; 
    return wantarray ? (reguuid => $reguuid, regid => encode_base64($regid) ) : $regid;
 }

 sub pubKeyOfAuth {
  use ECC qw(EC);
  my ($name,$passcode,$realm,$devuid,$args) = args([qw(name passcode realm devuid)],@_);
  my $auth64 = encode_base64(join':',$name,$passcode,$realm);
     $devuid = decode_uuid( ${devuid} || 'b75eefdb-ac81-4a73-ab88-3d63017bcc73' );
  my $deviceid = pubKeyOf($devuid);
  my $regid = decode_uuid( $args->{regid} // '46cbd7ef-02bb-4ba9-8f40-a6cf021f4c1d' );

  my $cnt = $args->{cnt} // $cnts->{$regid} // 0;; # <--
  my $sku = KDF::SK($auth64,$devuid,'sku',$cnt);
  my $pku = EC($sku);

  my $pku58 = encode_mbase58($pku);
  my $sku58 = encode_mbase58($sku);
  return wantarray ? (public  => $pku58, private => $sku58, deviceid => $deviceid) : $pku;

}

sub pubKeyOf {
  use env qw(ENV);
  use ECC qw(EC);
  use XKH qw(KH);
  my $uuid = $_[0]; delete $_[0] && shift;
  my $seedi58 = ENV('SECRET_PRIVATE_KEY' => '21c01ac5-3174-4217-9059-1b2b0e426932');
  my $seedi = decode_mbase($seedi58);
  my $privkey = KH($seedi,$uuid,$VERSION,substr($uuid,-1));
  SECURE "privkey: %s",$privkey;
  my $pubkey = EC($privkey);
  return wantarray ? (public  => encode_mbase58($pubkey), private => encode_mbase58($privkey), seedi => $seedi58) : $pubkey;
}


 sub getSpotByKey { # Ex. my $spot = getSpot($key,$env);
    use spots;
    my $spot64;
    my $key64 = encode_base64(shift);
    if (exists $spots->{$key64}) {
      $spot64 = $spots->{$key64};
    } else {
      my $ip = &spots::get_ip(@_);
      $spot64 = $spots->{$key64} = encode_spot($ip,time);
      &spots::saveSpots();
    }
    my ($loc,$tic) = &encode::decode_spot(decode_base64($spot64));
    DEBUG "spot: %s # %s \@ %s",$spot64,$loc,&wdate($tic);
    return $spot64
 }

 sub encode_spot { # Ex. my $spot64 = &get_spot($ip,$tics); # spacetime format
  my ($dotip,$tics) = @_;
  my $spot = pack'C4N',split('\.',$dotip),int($tics);
  return encode_base64($spot,'');
}

 sub getTofuByKey { # Ex. my $tofu = getTofu();
    # --- time ---
    use tofus;
    my $tofu;
    my $key = shift;
    if (exists $tofus->{$key}) {
      $tofu = $tofus->{$key};
    } else {
      $tofu = $tofus->{$key} = time;
      &tofus::saveTofus();
    }
    DEBUG "tofu: %s",$tofu;
    return $tofu
 }

1;
