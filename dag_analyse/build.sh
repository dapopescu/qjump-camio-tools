#!/bin/bash

echo "Building with args="  $@
cake dag_analyse.c $@ --append-CXXFLAGS="-D_GNU_SOURCE" --append-LINKFLAGS="-lcrypto -lssl"

