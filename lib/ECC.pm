package ECC;

our @EXPORT = qw(EC);

sub EC($) {
  my $private_raw = shift;
  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
  my $sk  = Crypt::PK::ECC->new();
  my $priv = $sk->import_key_raw($private_raw, $curve);
  my $public_raw = $sk->export_key_raw('public_compressed');
  return $public_raw;
}
sub DH {
  my $curve = 'secp256k1';
  my $public_raw =  pop;
  my $private_raw = shift;
  use Crypt::PK::ECC qw();
  my $sk  = Crypt::PK::ECC->new();
  my $priv = $sk->import_key_raw($private_raw, $curve);
  my $pk = Crypt::PK::ECC->new();
  my $pub = $pk->import_key_raw($public_raw ,$curve);
  my $shared_secret = $priv->shared_secret($pub);
  return $shared_secret;
}

sub import {
    my $caller = caller;
    no strict 'refs';
    *{$caller.'::ENV'} = \&ENV;
    if (@_) {
       for (@_) {
          *{$caller."::$_"} = \&{$_};
       }
    } else {
       for (@EXPORT) {
          *{$caller."::$_"} = \&{$_};
       }
    }
}

1;
