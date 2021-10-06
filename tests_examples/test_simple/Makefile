# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

# to make on Ubuntu, requires:
# sudo apt install gcc-aarch64-linux-gnu
# sudo apt-get install gcc-9-arm-linux-gnueabihf 
CC_OPTS := -Wall

OUT_ARCHES := x86 aarch64 arm

TEST_OUTS := $(patsubst %, test.%.out, ${OUT_ARCHES})

all: ${TEST_OUTS}

%.x86.out: CC=gcc
%.aarch64.out: CC=aarch64-linux-gnu-gcc
%.arm.out: CC=arm-linux-gnueabihf-gcc-9

test.%.out: test.c
	${CC} ${CC_OPTS} $< -o $@

clean:
	rm -f *.out
