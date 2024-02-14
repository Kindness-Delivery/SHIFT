package import;
# $Intent: act in Pure Kindness $
# 
# $Author: michelc $
# $Created-On: Wed, 2024-01-24 13:17:08 $
# $Last-Modified: Wed, 2024-01-24 13:29:32 $
# .-2! echo "\# \$Created-On: $(date -d @$(stat -c \%Y %~1)  +'\%a, \%Y-\%m-\%d \%T') \$"
# .-2! echo "\# \$Last-Modified: $(date +'\%a, \%Y-\%m-\%d \%T') \$"
# $! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"

our @EXPORT = qw(import);
sub import {
    my $caller = caller;
    no strict 'refs';
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
1; # $Source: /ipfs/QmbUDrb8px6pFYxuoen6yzPj8qpKSY2hQUnjyw1TZiBmG7/import.pm $
