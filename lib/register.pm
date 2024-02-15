#!/bin/perl


package register;
use Exporter qw(import);
our @EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};


use kanony;
use encode;
sub DEBUG{};
use IDE;

sub register {
   use KLUT;
   use XKH qw(KH DH KM);
   my $key = getRegKey(@_);
   my $reginfo = getRegId(@_);
   my $regid = $reginfo->{reguuid};

   # get pku to get session key...
   my ($name,$passcode,$mnemo,$args) = args([qw(name passcode mnemo)],@_);
   my $pku58 = $args->{pubkey} || 'Z223CLvvTBagprnX1aZq2AuR5cVVd7VkfbfnnoBy5HAr3G';
   my $pku = decode_mbase58($pku58);
   


   my $weekly = int $tofu/3600/24/7 * OPHI;
   my $sessionid = $args->{sessionid} || $weekly;

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', 1686197);
   my $seedr = decode_mbase($seedr64);
   my $sks = KH($seedr,$regid,$name,$sessionid);


   my $secret = DH($sks, $pku);
   my $seedk = KM($secret,'seed',$pku); # to protect KLUT
   KLUT($seedk,$key,$regid);
   
}
sub getRegKey { # Ex. my $regkey = getRegId($name,$secret,$URI, access => $access);
    use KDF;
    use misc qw(args);
    my ($name,$secret,$mnemo,$args) = args([qw(name secret mnemo)],@_);
    my $key = encode_base64(KDF($name,$secret,$mnemo, @_)); # /!\ make sure $name + $mnemo are unique
    return $key;
}

sub getRegId { # Ex. my $reginfo = getRegId($name,$secret,$URI);
    use misc qw(args);
    use XKH qw(KH);
    my ($name,$secret,$mnemo,$args) = args([qw(name secret mnemo)],@_);
    # ----------------------------------------------------
    # --- spot ---
    my $spot = &getSpot($key,$env//\%ENV); # space & time
    my $seedr = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', 1686197);
    DEBUG "seedr: %s",$seedr;
    my $seedr_raw = decode_mbase($seedr);
    my $regid = KH($seedr_raw,$name,$spot); # <--- 
    my $reguuid = encode_uuid(substr($regid,-17,16));
    DEBUG "reguuid: %s # %s %s  %s",$reguuid,kaname($regid); 
    return wantarray ? (reguuid => $reguuid, regid => encode_base64($regid) ) : $regid;
 }

 sub pubKeyOfAuth {
  use XKH qw(EC);
  my ($name,$passcode,$realm,$devuid,$args) = args([qw(name passcode realm devuid)],@_);
  my $auth64 = encode_base64(join':',$name,$passcode,$realm);
  my $devuid = decode_uuid( $args->{devuid} || 'b75eefdb-ac81-4a73-ab88-3d63017bcc73' );
  my $deviceid = pubKeyOf($devuid);
  my $regid = decode_uuid( $args->{regid} // '46cbd7ef-02bb-4ba9-8f40-a6cf021f4c1d' );

  my $cnt = $args->{cnt} // $cnts->{$regid} // 0;;
  my $sku = KDF::SK($auth64,$devuid,'sku',$cnt);
  my $pku = EC($sku);

  my $pku58 = encode_mbase58($pku);
  my $sku58 = encode_mbase58($sku);
  return wantarray ? (public  => $pku58, private => $sku58, deviceid => $deviceid) : $pku;

}

sub pubKeyOf {
  use env qw(ENV);
  use XKH qw(KH EC);
  my $uuid = $_[0]; delete $_[0] && shift;
  my $seed = ENV('SECRET_PRIVATE_KEY' => '21c01ac5-3174-4217-9059-1b2b0e426932');
  my $seed_raw = decode_mbase($seed);
  my $privkey = KH($seed_raw,$uuid,$VERSION,substr($uuid,-1));
  my $pubkey = EC($privkey);
  return encode_mbase58($pubkey);
}


 sub getSpot { # Ex. my $spot = getSpot($env);
    use spots;
    my $spot;
    my $key = shift;
    if (exists $spots->{$key}) {
      $spot = $spots->{$key};
    } else {
      my $ip = &spots::get_ip(@_);
      $spot = $spots->{$key} = encode_spot($ip,time);
      &spots::saveSpots();
    }
    DEBUG "spot: %s",$spot;
    return $spot
 }

 sub encode_spot { # Ex. my $spot64 = &get_spot($ip,$tics); # spacetime format
  my ($dotip,$tics) = @_;
  my $spot = pack'C4N',split('\.',$dotip),int($tics);
  return encode_base64($spot,'');
}

 sub getTofu { # Ex. my $tofu = getTofu();
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
