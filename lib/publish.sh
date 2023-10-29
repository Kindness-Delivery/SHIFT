#
tics=$(date +%s)
SITE=$(readlink -f $(dirname $0)/..)
echo "--- # $0"

find . -name '*~1' -delete
ipfs add -n -w -r $SITE/lib $SITE/etc
qmsite=$(ipfs add -Q -w -r $SITE/lib $SITE/etc)
echo qmsite: $qmsite
qm=$(ipfs add -Q -r $PWD)
echo $tics: $qm >> qm.log
ipfs add -w *.p?
qmlib=$(ipfs add -n -Q -w *.p?)
f=a.pm
perl -pn \
 -e "s,({?[A-Z][A-Z_]+}?)=(['\"])?/ipfs/\w+(['\"])?,\$1=\2/ipfs/${qmsite}\3,;" \
 -e "s,-e '/ipfs/\w*',-e '/ipfs/$qmlib',;" \
 -e "s,use lib '/ipfs/\w*';,use lib '/ipfs/$qmlib';,;" \
 $f > $f~
if [ "$?" -eq 0 ]; then
  if ! diff --color $f $f~; then # ∃ a diff
    mv $f~ $f
  fi
fi

