#!/bin/bash

command -v uncrustify >/dev/null 2>&1 || exit 0

function format {
	if [ -f .uncrustify.cfg -a "$2" == "-l" ] ; then 
		uncrustify -q -l C -c .uncrustify.cfg --no-backup "$1"
	else
		uncrustify -q -l C -c uncrustify.cfg --no-backup "$1"
	fi
}

for d in src; do
	for e in c h c; do
		for file in $d/*.$e; do
			format "$file"
		done
	done
done

exit 0
