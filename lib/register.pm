#!/bin/perl


package register;
use Exporter qw(import);


sub DEBUG{};
use IDE;


sub getRegKey { # Ex. my $regkey = getRegId($name,$secret,$URI, access => $access);
    my ($name,$secret,$mnemo,$args) = args([qw(name secret mnemo],@_);
    my $key = encode_base64(KDF($name,$secret,$mnemo, @_)); # /!\ make sure $name + $mnemo are unique
    return $key;
}

sub getRegId { # Ex. my $reginfo = getRegId($name,$secret,$URI);
    my ($name,$secret,$mnemo,$args) = args([qw(name secret mnemo],@_);
    # ----------------------------------------------------
    # --- spot ---
    my ($error,$spot) = &getspot(); # space & time
    DEBUG "dotip: %s",$spot->{dotip};
    if ($error) { 
       return { error =>$error, message => "Wrong spot: $spot" };
    }

    my $seedr = &ENV('REGISTRATION_SEED' => '0fd406ae-a99c-4c82-8102-6b1cb449186f', 1686197);
    DEBUG "seedr: %s",$seedr;
    my $seedr_raw = decode_mbase($seedr);

 }

 sub getTofu { # Ex.
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


