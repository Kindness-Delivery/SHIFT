#!perl

use lib '/ipfs/QmWZMQHE6NW9AsrwLjtCHazFG4AseD3scRjtf1hcF3scoQ'; # Brandon 🌙 390
use LOG;
use redacted qw(get_pass);

*redacted::peek = \&LOG::TRACE;
*redacted::debug = \&LOG::TRACEF;

my $pass = &get_pass('secret',$$,undef);
printf "🔑 pass0: %s\n",$pass;
my $pass1 = &get_pass('secret',$$,'secret1');
printf "🔑 pass1: %s\n",$pass1;
my $pass0 = &get_pass('secret',$$,'pass0');
printf "🔑 pass0: %s\n",$pass0;


exit $?;
