#!/bin/bash
if [ -f "./state.bin" ]; then
    rm ./state.bin
fi

./brop.rb vuln-nginx-1.4.0-64
