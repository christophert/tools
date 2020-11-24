#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "[CN] [SAN] [outfile] [keyout] [configuration file]"
    exit 1
fi
export SAN="$2"
export CN="$1"

openssl ecparam -genkey -name brainpoolP256r1 -out $4
CONF=${5:-conf/certs_with_san.cnf}
openssl req -new -key $4 -nodes -out $3 -config $CONF
unset SAN
unset CN
