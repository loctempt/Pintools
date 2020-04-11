#!/bin/bash
if [ $# -lt 1 ]
then
	echo 'Usage: concat_inst_func.sh [file index] [output filename]'
else
	out_file=cat$1.out
	if [ $# == 2 ]
	then
		out_file=$2
	fi
	echo output file: $out_file
	cat $1.*.out | sort -n -k 1 -t ' ' > $out_file
fi
