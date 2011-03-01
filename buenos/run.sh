#!/bin/bash

if [ ""$1 = "" ]; then
    echo "usage: $0 file"
    exit 1
fi

fyams-sim buenos 'initprog=[arkimedes]'$1
