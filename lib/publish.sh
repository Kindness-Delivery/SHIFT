#

tics=$(date +%s)
find . -name '*~1' -delete
qm=$(ipfs add -Q -r $PWD)
echo $tics: $qm >> qm.log
ipfs add -w *.pm *.pl
