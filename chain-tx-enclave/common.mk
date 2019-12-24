# Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of Baidu, Inc., nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# Modifications Copyright 2019 Foris Limited (licensed under the Apache License, Version 2.0)

######## Update SGX SDK ########
# include ../UpdateRustSGXSDK.mk
######## SGX SDK Settings ########

SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= SW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
else
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
endif

CARGO_FLAGS := --no-default-features --features mesalock_sgx
ifeq ($(SGX_DEBUG), 1)
	OUTPUT_PATH := debug
else
	OUTPUT_PATH := release
	CARGO_FLAGS += --release
endif

ifeq ($(SGX_TEST), 1)
	CARGO_FLAGS += --features "sgx-test"
endif

######## App Files ############
CARGO_TARGET_DIR ?= ../../target
Enclave_Static_Lib := $(CARGO_TARGET_DIR)/$(OUTPUT_PATH)/lib$(Enclave_Name).a
Enclave_Shared_Lib := $(CARGO_TARGET_DIR)/$(OUTPUT_PATH)/lib$(Enclave_Name).so
Enclave_Signed_Lib := $(CARGO_TARGET_DIR)/$(OUTPUT_PATH)/$(Enclave_Name).signed.so

######## Compiler Flags ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

Compiler_RT_Lib := ../rust-sgx-sdk/compiler-rt/libcompiler-rt-patch.a
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tcxx -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) \
   	$(Compiler_RT_Lib) $(Enclave_Static_Lib) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=enclave/Enclave.lds

.PHONY: all
all: $(Enclave_Signed_Lib)

$(Enclave_Shared_Lib): $(Enclave_Static_Lib) $(Compiler_RT_Lib)
	@$(CXX) -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Signed_Lib): $(Enclave_Shared_Lib)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $< -out $@ -config enclave/Enclave.config.xml
	@echo "SIGN => $@"

$(Enclave_Static_Lib): FORCE
	@cd ./enclave/ && cargo build ${CARGO_FLAGS}
	@echo "CARGO => $@"

$(Compiler_RT_Lib):
	$(MAKE) -C ../rust-sgx-sdk/compiler-rt

.PHONY: clean
clean:
	@rm -f $(Enclave_Shared_Lib) $(Enclave_Signed_Lib)
	$(MAKE) -C ../rust-sgx-sdk/compiler-rt clean

FORCE:
