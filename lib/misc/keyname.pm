#!/usr/bin/perl

package misc::keyname;
use strict;
use vars qw/$dbug/;
#ur @EXPORT = qw(firtsname shortkey);
# -----------------------------------------------------------------------
sub shortkey {
  if (defined $_[0]) {
    my $qm = shift;
    if ($qm =~ m/^(?:Qm|[Zmfb])/) {
      return substr($qm,0,5).'..'.substr($qm,-4);
    } else {
      return substr($qm,0,6).'..'.substr($qm,-3);
    }
  } else {
    return 'undefined';
  }
}
# -----------------------------------------------------------------------
sub keyname {
  return qw(
    James John Robert Michael William Mary David Richard Charles Joseph Thomas Christopher
    Patricia Daniel Linda Paul Mark Donald George Barbara Elizabeth Jennifer Kenneth Steven
    Edward Maria Brian Susan Ronald Anthony Margaret Dorothy Kevin Jason Matthew Gary Lisa
    Timothy Nancy Karen Betty Jose Helen Larry Jeffrey Sandra Frank Scott Eric Stephen Donna
    Andrew Carol Ruth Raymond Sharon Michelle Laura Sarah Kimberly Deborah Jessica Shirley
    Gregory Joshua Cynthia Angela Jerry Melissa Brenda Amy Dennis Anna Walter Rebecca Virginia
    Kathleen Patrick Pamela Martha Peter Debra Amanda Harold Stephanie Douglas Henry Carolyn
    Christine Marie Janet Carl Catherine Frances Ann Joyce Arthur Diane Alice Ryan Roger Julie
    Joe Juan Jack Albert Jonathan Heather Justin Terry Teresa Doris Gloria Gerald Keith Samuel
    Willie Evelyn Jean Cheryl Mildred Katherine Ralph Joan Lawrence Ashley Nicholas Judith Rose
    Roy Benjamin Janice Bruce Kelly Brandon Adam Nicole Judy Christina Kathy Harry Fred Theresa
    Wayne Billy Beverly Steve Denise Louis Jeremy Aaron Tammy Irene Randy Jane Howard Eugene Lori
    Carlos Russell Rachel Marilyn Bobby Victor Andrea Kathryn Martin Ernest Phillip Todd Louise
    Sara Anne Jacqueline Jesse Wanda Bonnie Julia Craig Ruby Lois Alan Tina Phyllis Norma Paula
    Shawn Diana Annie Clarence Sean Philip Chris Johnny Lillian Earl Emily Robin Peggy Crystal
    Jimmy Antonio Danny Bryan Tony Gladys Luis Mike Rita Dawn Stanley Leonard Nathan Connie
    Florence Dale Tracy Edna Tiffany Manuel Rodney Carmen Curtis Rosa Cindy Norman Grace Allen
    Wendy Marvin Vincent Glenn Victoria Jeffery Travis Jeff Edith Chad Jacob Kim Sherry Sylvia
    Josephine Lee Melvin Alfred Thelma Shannon Sheila Ethel Kyle Francis Ellen Elaine Marjorie
    Bradley)[(shift)%256];
}
sub keymoji {
  use Encode qw();
  our @ab = split('',Encode::decode_utf8(
    '👍👎👊✌✋👌👏👋👆👇👈👉✍👁👂👃'.
    '👣🤖❌➕➖➗✔❗❓⁉🎌💯💋💍💎❤'.
    '🎸🎷🎹🎻🏈🏀⚽⚾🏆🏁🏹🏅🏐☁🌪🌧'.
    '🌩➰🐔🐧🐋🦀🐒🐑🐍🐎🐘🐙🐢🐝🐖🐊'.
    '🐁🐄🐦🐌🐫🐬🐉🕷🕸🐈🐇🐜🐟🍣🍨🍩'.
    '🍪🍫🍭🍔🍕🍞🎂🌮🌭🧀🍙🍝🍿🍎🍍🍌'.
    '🍇🍉🍒🍓🍊🍋🍑🍐🍄🍅🍆🌶🌽🍷🍺☕'.
    '🍸🍾🎃🎄🎅🎁☃❄⌚⌛⏰☎🎈🎉🎊🎆'.
    '👻💀👿👽☀🌈🌙☔⭐🌵🌹🌻🍀🍁🌱🌴'.
    '💄💅🎩🎤🎥🎨🎲⚠📷💰💳💲♠♣♥♦'.
    '🚀🚒🚗🚢🚫🚲🚜🚁✈🚦💾💿📡📖📅📋'.
    '📎📏📌✏✂🔍🔑🔒🔪🔫🔧🔨🍴🔥💣🚬'.
    '👠👟👕👖👙👗👔👑👓👜💩🚽🚿🛀🎓🌋'.
    '⛪🆗🎀💊💉🔔🔬🕯◀▶⬅⬆⬇↗↖↘'.
    '↙↩↪🔄⏩⏪⏫⏬⏸✨☮☢☯✡⚓⚙'.
    '🎢🎡🎪🚩🎬🎮🎰🎱🎵🎺🎿🏋🏭👅👀👯'));
  return $ab[(shift)%256];
}
# -----------------------------------------------------------------------
sub import {
    my $caller = caller;
    my $pkg = shift;
    no strict 'refs';
    for (@_, 'keyname') {
      *{$caller . "::$_"} = \&{$_};
    }
}
# -----------------------------------------------------------------------
# .+2! echo "1; \# \$Source: /ipfs/$(ipfs add -w % -Q)/%:t \$"
# -----------------------------------------------------------------------
1; # $Source: $
