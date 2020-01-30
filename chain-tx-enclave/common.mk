# Copyright (c) 2017-2020 Apache Teaclave Authors (licensed under the Apache License, Version 2.0)
#
# Modifications Copyright 2018-2020 Foris Limited (licensed under the Apache License, Version 2.0)

######## Update SGX SDK ########
# include ../UpdateRustSGXSDK.mk
######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

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

CARGO_FLAGS :=
ifeq ($(SGX_DEBUG), 1)
	OUTPUT_PATH := debug
else
	OUTPUT_PATH := release
	CARGO_FLAGS += --release
endif

ifeq ($(SGX_TEST), 1)
	CARGO_FLAGS += --features "sgx-test"
endif

######## Enclave Files ############
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
