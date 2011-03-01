#!/bin/bash

if [ ""$1 = "" ]; then
    echo "usage: $0 file"
    exit 1
fi

rm -f tests/$1
make -C tests

./util/tfstool delete fyams.harddisk $1
./util/tfstool write fyams.harddisk tests/$1 $1
