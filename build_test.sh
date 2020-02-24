#!/bin/sh

baseDir=.
srcDir=$baseDir/src
includeDir=$baseDir/include

if [ -z ${CXX+x} ]; then CXX=c++; fi

$CXX -Ofast -Wall -march=native -std=c++11 -I ./include $srcDir/main.cpp -o aes-brute-force -lpthread $*
