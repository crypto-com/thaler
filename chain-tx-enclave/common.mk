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

# turn on stack protector for SDK
COMMON_FLAGS += -fstack-protector

ifdef DEBUG
    COMMON_FLAGS += -O0 -g -DDEBUG -UNDEBUG
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG
endif

# turn on compiler warnings as much as possible
COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
		-Waddress -Wsequence-point -Wformat-security \
		-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
		-Wcast-align -Wconversion -Wredundant-decls
# additional warnings flags for C
CFLAGS += -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

# additional warnings flags for C++
CXXFLAGS += -Wnon-virtual-dtor

# for static_assert()
CXXFLAGS += -std=c++0x

ifeq ($(ARCH), x86)
COMMON_FLAGS += -DITT_ARCH_IA32
else
COMMON_FLAGS += -DITT_ARCH_IA64
endif

CFLAGS   += $(COMMON_FLAGS)
CXXFLAGS += $(COMMON_FLAGS)

# Enable the security flags
COMMON_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack

MITIGATION-CVE-2020-0551 ?= LOAD

# mitigation options
MITIGATION_INDIRECT ?= 0
MITIGATION_RET ?= 0
MITIGATION_C ?= 0
MITIGATION_ASM ?= 0
MITIGATION_AFTERLOAD ?= 0
MITIGATION_LIB_PATH :=

ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
    MITIGATION_C := 1
    MITIGATION_ASM := 1
    MITIGATION_INDIRECT := 1
    MITIGATION_RET := 1
    MITIGATION_AFTERLOAD := 1
    MITIGATION_LIB_PATH := cve_2020_0551_load
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
    MITIGATION_C := 1
    MITIGATION_ASM := 1
    MITIGATION_INDIRECT := 1
    MITIGATION_RET := 1
    MITIGATION_AFTERLOAD := 0
    MITIGATION_LIB_PATH := cve_2020_0551_cf
endif

MITIGATION_CFLAGS :=
MITIGATION_ASFLAGS :=
ifeq ($(MITIGATION_C), 1)
ifeq ($(MITIGATION_INDIRECT), 1)
    MITIGATION_CFLAGS += -mindirect-branch-register
endif
ifeq ($(MITIGATION_RET), 1)
    MITIGATION_CFLAGS += -mfunction-return=thunk-extern
endif
endif

ifeq ($(MITIGATION_ASM), 1)
    MITIGATION_ASFLAGS += -fno-plt
ifeq ($(MITIGATION_AFTERLOAD), 1)
    MITIGATION_ASFLAGS += -Wa,-mlfence-after-load=yes
else
    MITIGATION_ASFLAGS += -Wa,-mlfence-before-indirect-branch=register
endif
ifeq ($(MITIGATION_RET), 1)
    MITIGATION_ASFLAGS += -Wa,-mlfence-before-ret=not
endif
endif

MITIGATION_CFLAGS += $(MITIGATION_ASFLAGS)

# Compiler and linker options for an Enclave
#
# We are using '--export-dynamic' so that `g_global_data_sim' etc.
# will be exported to dynamic symbol table.
#
# When `pie' is enabled, the linker (both BFD and Gold) under Ubuntu 14.04
# will hide all symbols from dynamic symbol table even if they are marked
# as `global' in the LD version script.
ENCLAVE_CFLAGS   = -ffreestanding -nostdinc -fvisibility=hidden -fpie -fno-strict-overflow -fno-delete-null-pointer-checks
ENCLAVE_CXXFLAGS = $(ENCLAVE_CFLAGS) -nostdinc++
ENCLAVE_LDFLAGS  = $(COMMON_LDFLAGS) -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                   -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                   -Wl,--gc-sections \
                   -Wl,--defsym,__ImageBase=0

ENCLAVE_CFLAGS += $(MITIGATION_CFLAGS)
ENCLAVE_ASFLAGS = $(MITIGATION_ASFLAGS)

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

RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tcxx -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) \
   	$(Enclave_Static_Lib) -Wl,--end-group \
	-Wl,--version-script=enclave/Enclave.lds \
	$(ENCLAVE_LDFLAGS)

.PHONY: all
all: $(Enclave_Signed_Lib)

$(Enclave_Shared_Lib): $(Enclave_Static_Lib)
	@$(CXX) -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Signed_Lib): $(Enclave_Shared_Lib)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $< -out $@ -config enclave/Enclave.config.xml
	@echo "SIGN => $@"

$(Enclave_Static_Lib): FORCE
	@cd ./enclave/ && cargo build ${CARGO_FLAGS}
	@echo "CARGO => $@"

.PHONY: clean
clean:
	@rm -f $(Enclave_Shared_Lib) $(Enclave_Signed_Lib)

FORCE:
