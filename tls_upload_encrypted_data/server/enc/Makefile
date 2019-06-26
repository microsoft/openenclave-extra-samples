# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        CXX = clang++-7
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

.PHONY: all build clean run

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) sign

# The client in the sample will need to know the enclave's public key, so
# we produce a C header to make it easy to load.
genkey: public.pem
	chmod u+x ../../scripts/gen_pubkey_header.sh
	../../scripts/gen_pubkey_header.sh ../../common/tls_server_enc_pubkey.h $<

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --trusted --trusted-dir .
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ecalls.cpp server.cpp crypto.cpp ../../common/utility.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) tls_server_t.c
	$(CXX) -o tls_server_enc ecalls.o server.o crypto.o utility.o tls_server_t.o $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore -loelibc -loesyscall

sign:
	oesign sign -e tls_server_enc -c enc.conf -k private.pem

clean:
	rm -f *.o tls_server_enc tls_server_enc.signed tls_server_enc.signed.so tls_server_t.* tls_server_args.h ../../common/tls_server_enc_pubkey.h
