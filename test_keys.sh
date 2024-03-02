#!/bin/bash
set -uo pipefail
trap 's=$?; echo ": Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR
IFS=$'\n\t'

make clean cli.min.js

for e in 3 17 257 65537 4294967297
do
  for bits in 1024 2048 3072 4096 `seq 1536 4 1600`
  do
    openssl genpkey \
      -algorithm RSA \
      -pkeyopt rsa_keygen_bits:$bits \
      -pkeyopt rsa_keygen_pubexp:$e \
      -out tmp.key 2> /dev/null
    openssl req \
      -key tmp.key \
      -x509 \
      -days 365 \
      -subj '/CN=test' \
      -out tmp.crt
    FP_JS=$(node cli.min.js tmp.crt | sed 's/.*: //')
    FP_PY=$(python3 tasmota_fingerprint.py tmp.crt | sed 's/.*: //')
    if [ "$FP_JS" == "$FP_PY" ]
    then
      printf 'OKAY %s (bits:%s exp:%s)\n' "$FP_JS" $bits $e
    else
      printf 'FAIL %s (bits:%s exp:%s)\n' "$FP_JS" $bits $e
    fi
  done
done

rm tmp.key tmp.crt
