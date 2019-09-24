# adapted from https://github.com/scs/substraTEE-worker (SubstraTEE worker`)
# Copyright (c) 2019, Supercomputing Systems AG (licensed under the Apache License, Version 2.0)
# helper script to update the files in rust-sgx-sdk to the lastest version

GIT = git
CP  = cp

REPO = https://github.com/baidu/rust-sgx-sdk.git
SDK_PATH_GIT = rust-sgx-sdk-github
SDK_PATH = ./rust-sgx-sdk
VERSION_FILE = ./rust-sgx-sdk/version
LOCAL_VERSION = $(shell cat $(VERSION_FILE))
COMMAND = git ls-remote $(REPO) HEAD | awk '{ print $$1 }'
REMOTE_VERSION = $(shell $(COMMAND))

# update the SDK files
all: updatesdk

updatesdk:
# check for already updated version
ifneq ('$(LOCAL_VERSION)','$(REMOTE_VERSION)')
	@echo Local version = $(LOCAL_VERSION)
	@echo Remote version = $(REMOTE_VERSION)

	@rm -rf $(SDK_PATH_GIT)
	@$(GIT) clone $(REPO) $(SDK_PATH_GIT)
	rsync -a $(SDK_PATH_GIT)/edl $(SDK_PATH)
	rsync -a $(SDK_PATH_GIT)/common $(SDK_PATH)
	rsync -a $(SDK_PATH_GIT)/compiler-rt $(SDK_PATH)
	rm -rf $(SDK_PATH_GIT)
	@echo $(REMOTE_VERSION) > $(VERSION_FILE)

endif
