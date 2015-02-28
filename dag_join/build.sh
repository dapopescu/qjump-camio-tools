#!/bin/bash

echo "Building with args="  $@
cake dag_join.c $@ --append-CXXFLAGS="-D_GNU_SOURCE"

