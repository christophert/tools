#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "[CN] [SAN] [outfile] [keyout] [configuration file]"
    exit 1
fi
export SAN="$2"
export CN="$1"
CONF=${5:-conf/certs_with_san.cnf}
openssl req -out $3 -newkey rsa:2048 -nodes -keyout $4 -config $CONF
unset SAN
unset CN
