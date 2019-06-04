#!/usr/bin/env bash
#
# This script runs the storage benchmark and plots the results.
#
# Resulting PNG plots will be saved in the current working directory that
# the script is called from.
#
# Storage backend name can optionally be passed as the first argument to
# this script (memory backend is used by default).  The optional second
# argument specifies the data directory for the storage backend.
#

set -o errexit -o nounset -o pipefail

# Get the full path to the root of the ekiden repository.
ROOT="$(cd $(dirname $0)/..; pwd -P)"

# Select storage backend to test.
BACKEND="memory"
if [[ $# == 1 ]]; then
	BACKEND="$1"
elif [[ $# == 2 ]]; then
	BACKEND="$1"
	DATADIR="$2"
elif [[ $# != 0 ]]; then
	echo "Usage: $0 [backend [datadir]]"
	exit 1
fi

# Check if we have all the tools we need.
if [[ "$(which gnuplot)" == "" ]]; then
	echo "ERROR: gnuplot not installed.  Install it and try again."
	exit 1
fi
if [[ ! -x ${ROOT}/go/ekiden/ekiden ]]; then
	echo "ERROR: ekiden command isn't built.  Run 'make' in '${ROOT}/go' and try again."
fi

# Run benchmarks.
ARGS="storage benchmark --log.level INFO --storage.backend ${BACKEND}"
if [[ -n ${DATADIR+x} ]]; then
	ARGS="${ARGS} --datadir ${DATADIR}"
fi
OUT="$(mktemp)"
${ROOT}/go/ekiden/ekiden ${ARGS} > ${OUT}

# CAS Insert.
DATA_INSERT="$(mktemp)"
fgrep 'msg=Insert sz=' ${OUT} | cut -sd' ' -f6,7 | sed 's/[^0-9 ]*//g' > ${DATA_INSERT}

gnuplot <<- EOF
set title "CAS Insert (${BACKEND})"

set logscale x
set xlabel "Value size [log bytes]"
set xtics (256, 512, 1024, 4096, 8192, 16384, 32768)

set ylabel "μs/op"

set term png
set output "${BACKEND}_cas_insert.png"
plot '${DATA_INSERT}' using 1:(column(2) / 1000) with lines notitle
EOF

rm "${DATA_INSERT}"


# CAS Get.
DATA_GET="$(mktemp)"
fgrep 'msg=Get sz=' ${OUT} | cut -sd' ' -f6,7 | sed 's/[^0-9 ]*//g' > ${DATA_GET}

gnuplot <<- EOF
set title "CAS Get (${BACKEND})"

set logscale x
set xlabel "Value size [log bytes]"
set xtics (256, 512, 1024, 4096, 8192, 16384, 32768)

set ylabel "μs/op"

set term png
set output "${BACKEND}_cas_get.png"
plot '${DATA_GET}' using 1:(column(2) / 1000) with lines notitle
EOF

rm "${DATA_GET}"


# MKVS single Apply.
DATA_APPLY_SINGLE="$(mktemp)"
fgrep 'msg=Apply sz=' ${OUT} | cut -sd' ' -f6,7 | sed 's/[^0-9 ]*//g' > ${DATA_APPLY_SINGLE}

gnuplot <<- EOF
set title "MKVS single Apply (${BACKEND})"

set logscale x
set xlabel "Value size [log bytes]"
set xtics (256, 512, 1024, 4096, 8192, 16384, 32768)

set ylabel "μs/op"

set term png
set output "${BACKEND}_mkvs_single_apply.png"
plot '${DATA_APPLY_SINGLE}' using 1:(column(2) / 1000) with lines notitle
EOF

rm "${DATA_APPLY_SINGLE}"


# MKVS GetValue.
DATA_GETVALUE="$(mktemp)"
fgrep 'msg=GetValue sz=' ${OUT} | cut -sd' ' -f6,7 | sed 's/[^0-9 ]*//g' > ${DATA_GETVALUE}

gnuplot <<- EOF
set title "MKVS GetValue (${BACKEND})"

set logscale x
set xlabel "Value size [log bytes]"
set xtics (256, 512, 1024, 4096, 8192, 16384, 32768)

set ylabel "μs/op"

set term png
set output "${BACKEND}_mkvs_getvalue.png"
plot '${DATA_GETVALUE}' using 1:(column(2) / 1000) with lines notitle
EOF

rm "${DATA_GETVALUE}"


# MKVS batch Apply.
DATA_APPLY_BATCH="$(mktemp)"
fgrep 'msg=Apply bsz=' ${OUT} | cut -sd' ' -f6,7,8 | sed 's/[^0-9 ]*//g' | awk 'BEGIN{cur="1"; print "1"}{if ($1 != cur) {cur=$1; print "\n\n" $1;} print $0;}' > ${DATA_APPLY_BATCH}

gnuplot <<- EOF
set title "MKVS batch Apply (${BACKEND})"
set key top center

set logscale x
set xlabel "Value size [log bytes]"
set xtics (256, 512, 1024, 4096, 8192, 16384, 32768)

set ylabel "μs/op"

set term png
set output "${BACKEND}_mkvs_batch_apply.png"
stats '${DATA_APPLY_BATCH}' using 2:3 nooutput
plot for [i=0:STATS_blocks-1] '${DATA_APPLY_BATCH}' index i using 2:(column(3) / 1000) with lines title columnheader(1)
EOF

rm "${DATA_APPLY_BATCH}"

# Save raw benchmark data.
mv "${OUT}" "${BACKEND}_benchmarks.txt"
