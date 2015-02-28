#!/bin/bash

echo "Building with args="  $@
cake dag_capture.c $@ --append-CXXFLAGS="-D_GNU_SOURCE"

