#!/bin/bash

if [ "$#" -ne 5 ]; then
    echo "[CN] [SAN] [certout] [keyout] [configuration file]"
    exit 1
fi
export SAN="$2"
export CN="$1"
openssl req -x509 -days 365 -out $3 -newkey rsa:2048 -nodes -keyout $4 -config $5 -extensions 'v3_req'
unset SAN
unset CN
