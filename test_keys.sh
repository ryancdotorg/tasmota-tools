#!/bin/bash
set -uo pipefail
trap 's=$?; echo ": Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR
IFS=$'\n\t'

make clean cli.min.js

TESTDIR="test"

mkdir -p "$TESTDIR"

for e in 3 521 65537 4294967297
do
  if [ $e -eq 65537 ]
  then
    BITS=$(echo 1024 `seq 1536 8 2048` 3072 4096 | tr ' ' '\n')
  else
    BITS="2048	3072"
  fi

  for bits in $BITS
  do
    CERT="$TESTDIR/rsa_${bits}_${e}.crt"
    # generate the test certificate if it doesn't exist
    if [ ! -f "$CERT" ]
    then
      openssl genpkey \
        -algorithm RSA \
        -pkeyopt rsa_keygen_bits:$bits \
        -pkeyopt rsa_keygen_pubexp:$e \
        2> /dev/null | \
      openssl req \
        -key - \
        -x509 \
        -days 365 \
        -subj '/CN=test' \
        -out "$CERT"
    fi
    FP_JS=$(node cli.min.js "$CERT" | sed -E 's/\s+[(].*//')
    FP_PY=$(python3 tasmota_fingerprint.py "$CERT" | sed -E 's/\s+[(].*//')
    if [ "$FP_JS" == "$FP_PY" ]
    then
      printf 'OKAY %s (bits:%s exp:%s)\n' "$FP_JS" $bits $e
    else
      printf 'FAIL %s (bits:%s exp:%s)\n' "$FP_JS" $bits $e
    fi
  done
done
