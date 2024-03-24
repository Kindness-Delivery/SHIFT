#!/bin/perl


package register;
use Exporter qw(import);
our @EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};

# $Author: michelc $
# $Created-On: Tue, 2024-02-27 11:34:38 $
# $Last-Modified: Tue, 2024-02-27 11:35:09 $
# .-2! echo "\# \$Created-On: $(date -d @$(stat -c \%Y %~1)  +'\%a, \%Y-\%m-\%d \%T') \$"
# .-2! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -n -w % -Q)/%:t \$"

sub OPHI { (sqrt(5) - 1) * 11/13; }
use kanony;
use pwned qw(pwname);
use encode;
use misc;
use misc::date;
sub DEBUG{};
sub SECURE{};
use IDE;

our $cnts = {};

sub OPHI { (sqrt(5) - 1) * 11/13; }

sub sessionKey { # Ex. my $pks = sessionKey($name,$sessionid,$entropy,'uuid' => $uuid);
   use XKH qw(KH);
   use ECC qw(EC);
   use uuid qw(getUUID);
   my ($name,$sessionid,$entropy,$args) = args([qw(name sessionid entropy)],@_);
   # note: entropy not used !
   my $uuid = $args->{uuid} || 'af7d2ad1-2888-4d3b-a2f9-4d3075462ae9';

   my $weekly = int $^T/3600/24/7 * OPHI;
   $sessionid //= $args->{sessionid} || $weekly;
   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f',undef, $sessionid // 1686197);
   my $seedr = decode_mbase($seedr64);
   my $sks = KH($seedr,$uuid,$name,$sessionid);
   my $pks = EC($sks);
   return wantarray ? ( sessionid => $sessionid, uuid => $uuid,  private => encode_mbase58($sks), public => encode_mbase58($pks) ) : $pks;
}


sub register { # Ex. my $cipher = register($name,$passcode,"entropy for $name ". &ENV('$'), mnemo => 'special account', uuid => $uuid );
   use KDF;
   use uuid qw(getUUID);
   use KLUT;
   use XKH qw(KM XOR);
   my ($name,$passcode,$entropy,$args) = args([qw(name passcode entropy)],@_);
   my $regkey = KDF($name,$passcode,$args->{mnemo}//$entropy); # /!\ make sure $name + $mnemo are unique
   my $regkey64  = encode_base64($regkey);
   DEBUG "regkey64: %s # %s  %s %s",$regkey64,&pwname($regkey);

   # -------------------------------------------------------------
   my $uid = exists $args->{uuid} ? decode_uuid($args->{uuid}) : getUUID($name,$passcode,$entropy, comment => "uuid for $name");
   my $pki = pubKeyOf($uid,undef,$args->{cnt});
   # -------------------------------------------------------------


   my $weekly = int $^T/3600/24/7 * OPHI;
   my $sessionid = $args->{sessionid} || $weekly;
   DEBUG "sessionid: %s",$sessionid;

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f',undef, $sessionid // 1686197);
   my $seedr = decode_mbase($seedr64);
   my $seedk = KM($seedr,'seed',$entropy,$regkey); # key to protect KLUT
   DEBUG "regkey: %s",unpack'H*',$regkey;
   my $cipher = XOR($uid,$regkey);
   DEBUG "cipher: %s",unpack'H*',$cipher;
   # KLUT write ...
   my $access = KLUT($seedk,'uuid:'.$regkey64,$cipher);
   DEBUG "access: %s",unpack'H*',$access;
   return wantarray ? (access => $access, pubkey => encode_base58($pki) ) : $access ;
   
}

sub updRegistry {
   my ($regkey1,$regkey2,$nonce1,$nonce2) = @_;
   $nonce1 //= decode_uuid('06443b17-cb1a-4fe3-be2a-9d23e5322384');
   $nonce2 //= $nonce1; 
   my $value = getRegistry($nonce1,$regkey1);
   my $cipher = setRegistry($nonce2,$regkey2,$value);
   setRegistry($nonce,$regkey1,$revoked);
   return $cipher;
}


sub getIdentity {
   my ($name,$passcode,$entropy,$args) = args([qw(name passcode entropy)],@_);
   my $regkey = getRegKey(@_); # uses mnemo if defined
   my $regkey64  = encode_base64($regkey);

   my $weekly = int $^T/3600/24/7 * OPHI;
   my $sessionid = $args->{sessionid} || $weekly;

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', undef, $sessionid // 1686197);
   my $seedr = decode_mbase($seedr64);
   my $seedk = KM($seedr,'seed',$entropy,$regkey); # key to protect KLUT

   use XKH qw(XOR);
   my $cipher = KLUT($seedk,'uuid:'.$regkey64);
   my $uuid = XOR($cipher,$regkey);
   DEBUG "identity.uuid: %s # %s %s  %s",encode_uuid($uuid),kaname($uuid);
   my $pki = pubKeyOf($uuid,undef,$args->{cnt});
   return wantarray ? ( pki => encode_mbase58($pki), uuid => encode_uuid($uuid), regkey => encode_base64($regkey) ) : $pki;
}

sub getRegistry { # Ex. my $cipher = getRegistry($key,$nonce,'uuid');
   my ($regkey,$nonce,$args) = args([qw(regkey nonce)],@_);
   my $regkey64  = encode_base64($regkey);

   my $weekly = int ($^T//$args->{tofu}//$args->{tstamp})/3600/24/7 * OPHI;
   my $sessionid = $args->{sessionid} || $weekly;

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', undef, $sessionid // 1686197);
   my $seedr = decode_mbase($seedr64);
   my $seedk = KM($seedr,'seed',$nonce,$regkey); # key to protect KLUT

   my $cipher = KLUT($seedk,join':',@_,$regkey64);
   DEBUG "cipher: %s # %s %s  %s",encode_uuid($cipher),kaname($cipher);
   return $cipher;
}
sub setRegistry { # Ex. undef = getRegistry($key,$nonce,'uuid',$cipher);
   my ($regkey,$nonce,$cipher,$args) = args([qw(regkey nonce cipher)],@_);
   my $regkey64  = encode_base64($regkey);
   my $weekly = int ($^T//$args->{tofu}//$args->{tstamp})/3600/24/7 * OPHI;
   my $sessionid = $args->{sessionid} || $weekly;

   my $seedr64 = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', undef, $sessionid // 1686197);
   my $seedr = decode_mbase($seedr64);
   my $seedk = KM($seedr,'seed',$nonce,$regkey); # key to protect KLUT

   my $returned = KLUT($seedk,join(':',@_,$regkey64),$cipher);
   DEBUG "cipher: %s # %s %s  %s (registered)",encode_uuid($returned),kaname($returned);
   return (defined wantarray) ? $returned : undef;
}



sub getRegKey { # Ex. my $regkey = getRegId($name,$secret,$URI, access => $access);
    use KDF;
    use misc qw(args);
   my ($name,$passcode,$entropy,$args) = args([qw(name passcode entropy)],@_);
   my $regkey = KDF($name,$passcode,$args->{mnemo}//$entropy); # /!\ make sure $name + $mnemo are unique
    my $regkey64  = encode_base64($regkey);
    DEBUG "regKey64: %s # %s  %s %s for %s %s",$regkey64,pwname($regkey),$name,$args->{mnemo};
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
  use DH3 qw(pubKeyOf);
  use ECC qw(EC);
  my ($name,$passcode,$realm,$devuid,$args) = args([qw(name passcode realm devuid)],@_);
  my $auth64 = encode_base64(join':',$name,$passcode,$realm);
     $devuid = decode_uuid( ${devuid} || 'b75eefdb-ac81-4a73-ab88-3d63017bcc73' );
  my $deviceid = encode_base58(pubKeyOf($devuid));
  my $regid = decode_uuid( $args->{regid} // '46cbd7ef-02bb-4ba9-8f40-a6cf021f4c1d' );

  my $cnt = $args->{cnt} // $cnts->{$regid} // 0;; # <--
  my $sku = KDF::SK($auth64,$devuid,'sku',$cnt);
  my $pku = EC($sku);

  my $pku58 = encode_mbase58($pku);
  my $sku58 = encode_mbase58($sku);
  return wantarray ? (public  => $pku58, private => $sku58, deviceid => $deviceid) : $pku;

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

1; # $Source: /ipfs/QmYyU1Zy7CAndWnKA28xhcjMKeyz2ZFPgxyghCFPB9ViVF/register.pm $
