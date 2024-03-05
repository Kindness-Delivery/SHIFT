package import;
# $Intent: act in Pure Kindness $
# 
# $Author: michelc $
# $Created-On: Wed, 2024-01-24 13:17:08 $
# $Last-Modified: Tue, 2024-03-05 19:49:51 $
# .-2! echo "\# \$Created-On: $(date -d @$(stat -c \%Y %~1)  +'\%a, \%Y-\%m-\%d \%T') \$"
# .-2! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"

our @EXPORT = qw(import);

sub import {
  my $pkg = shift;
  my $caller = caller;
  no strict 'refs';
  for (@EXPORT) {
    if (defined &{$_}) {
      *{$caller."::$_"} = \&{$_};
    }
  }
  for (@{$pkg.'::EXPORT'}) {
    if (defined &{$pkg."::$_"}) {
      *{$caller."::$_"} = \&{$pkg."::$_"};
    }
  }
  for (@_) {
    if (defined &{$pkg."::$_"}) {
      *{$caller."::$_"} = \&{$pkg."::$_"};
    }
  }
  for (@{$pkg.'::EXPORT_OK'}) {
    if (exists ${$caller.'::'}{$_}) {
      *{$caller."::$_"} = \&{$pkg."::$_"};
    }
  }
}
1; # $Source: /ipfs/QmRjXhTCoLz5NZBobmnbWgV59DYjQvfmXWMRw4A9ma13J1/import.pm $
