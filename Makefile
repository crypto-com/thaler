RUST_LOG ?= info
# you can use devnet | testnet | mainnet
chain ?= devnet
# set the data path when the claster run
data_path ?= /tmp/data
# you can add a prefix such as node0 | node1 to create mulpile clusters on one host
prefix ?=
sgx_mode ?= HW
build_mode ?= debug
MAKE_CMD = make

# SGX_DEVICE can be /dev/sgx or /dev/isgx
SGX_DEVICE ?= /dev/sgx

ifeq ($(build_mode), release)
	CARGO_BUILD_CMD = cargo build --release
	SGX_MODE = "SGX_ARGS=0"
else
	SGX_ARGS =
	CARGO_BUILD_CMD = cargo build
endif


chain_abci_features ?= ${CHAIN_ABCI_FEATURES}
client_features ?= ${CLIENT_FEATURES}

ifeq ($(chain_abci_features)x, x)
	CARGO_BUILD_CMD_ABCI = $(CARGO_BUILD_CMD)
else
	CARGO_BUILD_CMD_ABCI = $(CARGO_BUILD_CMD) --features "$(chain_abci_features)"
endif

ifeq ($(client_features)x, x)
	CARGO_BUILD_CMD_CLI = $(CARGO_BUILD_CMD)
else
	CARGO_BUILD_CMD_CLI = $(CARGO_BUILD_CMD) --features "$(client_features)"
endif


base_port ?= 26650
TX_QUERY_PORT       = $(shell expr $(base_port) + 1)
TENDERMINT_P2P_PORT = $(shell expr $(base_port) + 6)
TENDERMINT_RPC_PORT = $(shell expr $(base_port) + 7)
CLIENT_RPC_PORT     = $(shell expr $(base_port) + 9)

# the chain version, such as v0.1.0, v0.2.0.
tag ?=
# if the tag not set, it will use current tag, if current code is not checkouted to a tag, it will use `develop`
ifeq ($(tag)x, x)
	TAG = $(shell git describe --exact-match --tags $(git log -n1 --pretty='%h') 2>/dev/null || echo develop)
else
	TAG = $(tag)
endif

# docker's network
NETWORK = crypto-chain

# if the TAG like v0.1.0, v0.2.0, we download the binary file from github
ifeq ($(TAG), develop)
	DOWNLAD_URL=
else
	DOWNLOAD_URL=$(shell curl -s https://api.github.com/repos/crypto-com/chain/releases \
            | grep browser_download_url \
            | grep download/$(tag)/ \
            | cut -d '"' -f 4 || echo "")
endif

APP_HASH := $(shell cat docker/config/$(chain)/tendermint/genesis.json | python -c "import json,sys;obj=json.load(sys.stdin);print(obj['app_hash'])")

ifeq ($(chain), devnet)
	CHAIN_ID   = test-chain-y3m1e6-AB
	NETWORK_ID = AB
	SGX_MODE   = $(sgx_mode)
else ifeq ($(chain), testnet)
	CHAIN_ID   = testnet-thaler-crypto-com-chain-42
	NETWORK_ID = 42
	SGX_MODE   = HW
else ifeq ($(chain), mainnet)
	CHAIN_ID   = thaler-crypto-com-chain-42
	NETWORK_ID = 42
	SGX_MODE   = HW
endif

IMAGE                  = crypto-chain
IMAGE_RUST             = cryptocom/chain
IMAGE_TENDERMINT       = tendermint/tendermint:v0.33.4
DOCKER_FILE            = docker/Dockerfile
DOCKER_FILE_RELEASE    = docker/Dockerfile.release
ITEMS_START            = sgx-query chain-abci tendermint client-rpc
ITEMS_STOP             = client-rpc tendermint chain-abci sgx-query

create-path:
	mkdir -p ${HOME}/.cargo/{git,registry}
	bash -c "mkdir -p $(data_path)/tendermint/{config,data}"
	bash -c "mkdir -p $(data_path)/{wallet,chain-storage,enclave-storage}"

init-tendermint:
ifeq ($(chain), devnet)
	@echo "\033[32mcopy devnet tendermint config\033[0m"
	cp docker/config/devnet/tendermint/config.toml $(data_path)/tendermint/config/
	cp docker/config/devnet/tendermint/genesis.json $(data_path)/tendermint/config/
	cp docker/config/devnet/tendermint/priv_validator_key.json $(data_path)/tendermint/config/
	cp docker/config/devnet/tendermint/priv_validator_state.json $(data_path)/tendermint/data/
else ifeq ($(chain), testnet)
	@echo "\033[32mcopy testnet tendermint config\033[0m"
	bash -c "cp docker/config/testnet/tendermint/{config.toml,genesis.json} $(data_path)/tendermint/config/"
else ifeq ($(chain), mainnet)
	@echo "\033[32mcopy mainnet tendermint config\033[0m"
	bash -c "cp docker/config/mainnet/tendermint/{config.toml,genesis.json} $(data_path)/tendermint/config/"
endif

install-sgx-driver:
ifeq ($(SGX_MODE), HW)
	@if [ -e "/dev/isgx" ] || [ -e "/dev/sgx" ]; then \
		echo "\033[32msgx driver already installed\033[0m"; \
	else \
		echo "\033[32install sgx driver\033[0m"; \
		curl --proto '=https' -sSf https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_4f5bb63.bin > /tmp/driver.bin && \
		chmod +x /tmp/driver.bin &&\
		sudo /tmp/driver.bin && \
		rm /tmp/driver.bin; \
	fi
else
	@echo "\033[32mSGX_MODE is SW, no need to install sgx driver\033[0m"
endif

# build the sgx image
image:
ifeq ($(DOWNLOAD_URL)X, X)
	@echo "\033[32mbuild docker image with local binary\033[0m";
	chmod +x ci-scripts/*.sh;
	docker build -t $(IMAGE):$(TAG) -f $(DOCKER_FILE)  --build-arg BUILD_MODE=$(build_mode) .
else
	@echo "\033[32mdownload binary and build docker image\033[0m";
	chmod +x docker/*.sh;
	docker build -t $(IMAGE):$(TAG) -f $(DOCKER_FILE_RELEASE) --build-arg DOWNLOAD_URL=$(DOWNLOAD_URL) .
endif

# build the chain binary in docker
build-chain:
	@if [ -e "./target/${BUILD_MODE}/client-cli" ] && [ -e "./target/${BUILD_MODE}/chain-abci" ] && [ -e "./target/${BUILD_MODE}/client-rpc" ] && [ -e "./target/${BUILD_MODE}/dev-utils" ]; then \
		echo "\033[32mbinary already exist or delete binary to force new build for chain\033[0m"; \
	else \
		echo "\033[32mbuilding binary\033[0m"; \
		docker run -i --rm \
			-v ${HOME}/.cargo/git:/root/.cargo/git \
			-v ${HOME}/.cargo/registry:/root/.cargo/registry \
			-v `pwd`:/chain \
			--env RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 \
			--workdir=/chain \
			$(IMAGE_RUST):latest \
			bash -c '. /root/.docker_bashrc && \
			echo "========  build dev-utils   =========" && \
			${CARGO_BUILD_CMD} --bin dev-utils && \
			echo "========  build chain-abci   =========" && \
			cd chain-abci && $(CARGO_BUILD_CMD_ABCI) && \
			echo "========  build client-cli   =========" && \
			cd ../client-cli && $(CARGO_BUILD_CMD_CLI)&& \
			echo "========  build client-rpc   =========" && \
			cd ../client-rpc && $(CARGO_BUILD_CMD_CLI)'; \
	fi

# build the enclave queury binary
build-sgx-query:
	@echo "\033[32mcompile sgx query\033[0m"; \
	docker run -i --rm \
		-v ${HOME}/.cargo/git:/root/.cargo/git \
		-v ${HOME}/.cargo/registry:/root/.cargo/registry \
		-v `pwd`:/chain \
		--env SGX_MODE=$(SGX_MODE) \
		--env RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 \
		--workdir=/chain \
		$(IMAGE_RUST):latest \
		bash -c ". /root/.docker_bashrc && \
		$(CARGO_BUILD_CMD) -p tx-query-app && \
		make -C chain-tx-enclave/tx-query $(SGX_ARGS)"

# build the enclave validation binary 
build-sgx-validation:
	@echo "\033[32mcompile sgx validation\033[0m"; \
	docker run -i --rm \
		-v ${HOME}/.cargo/git:/root/.cargo/git \
		-v ${HOME}/.cargo/registry:/root/.cargo/registry \
		-v `pwd`:/chain \
		--env NETWORK_ID=$(NETWORK_ID) \
		--env SGX_MODE=$(SGX_MODE) \
		--env RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 \
		--workdir=/chain \
		$(IMAGE_RUST):latest \
		bash -c " . /root/.docker_bashrc &&\
		make -C chain-tx-enclave/tx-validation ${SGX_ARGS}"


create-network:
	@if [ `docker network ls -f NAME=$(NETWORK) | wc -l ` -eq 2 ]; then \
		echo "network already exist"; \
	else \
		docker network create $(prefix)crypto-chain; \
	fi

rm-network:
	@echo "\033\[32mremove network ${NETWORK}\033[0m"
	docker network rm $(NETWORK)

run-sgx-query:
	@if [ "${SPID}x" = "x" ] || [ "${IAS_API_KEY}x" = "x" ]; then \
		echo "environment SPID and IAS_API_KEY should be set"; \
	else \
		echo "\033[32mrun docker sgx query\033[0m"; \
		docker run -d \
		--net $(NETWORK) \
		--restart=always \
		--name $(prefix)sgx-query \
		-e RUST_LOG=$(RUST_LOG) \
		-e SGX_MODE=$(SGX_MODE) \
		-e NETWORK_ID=$(NETWORK_ID) \
		-e SPID=${SPID} \
		-e IAS_API_KEY=${IAS_API_KEY} \
		-e TX_VALIDATION_CONN=ipc:///root/sockets/enclave.socket \
		-v ${HOME}/sockets:/root/sockets \
		--device $(SGX_DEVICE) \
		-p $(TX_QUERY_PORT):26651 \
		--workdir=/usr/local/bin \
		$(IMAGE):$(TAG) \
		bash ./run_tx_query.sh; \
	fi

run-abci:
	@echo "\033[32mrun docker chain-abci\033[0m"; \
	docker run -d \
	--net $(NETWORK) \
	--restart=always \
	-e RUST_LOG=$(RUST_LOG) \
	-e SGX_MODE=$(SGX_MODE) \
	-e NETWORK_ID=$(NETWORK_ID) \
	-e CHAIN_ID=$(CHAIN_ID) \
	-e PREFIX=$(prefix) \
	-e APP_HASH=$(APP_HASH) \
	-e TX_VALIDATION_CONN=ipc:///root/sockets/enclave.socket \
	--name $(prefix)chain-abci \
	-v $(data_path):/crypto-chain \
	-v ${HOME}/sockets:/root/sockets \
	--device $(SGX_DEVICE) \
	--workdir=/usr/local/bin \
	$(IMAGE):$(TAG) \
	bash ./run_chain_abci.sh

run-tendermint:
	@echo "\033[32mrun docker tendermint\033[0m"; \
	docker run -d \
	--net $(NETWORK) \
	--restart=always \
	--name $(prefix)tendermint \
	--user root \
	-v $(data_path)/tendermint:/tendermint \
	-p $(TENDERMINT_P2P_PORT):26656 \
	-p $(TENDERMINT_RPC_PORT):26657 \
	$(IMAGE_TENDERMINT) \
	node --proxy_app=$(prefix)chain-abci:26658 \
	--rpc.laddr=tcp://0.0.0.0:26657 \
	--consensus.create_empty_blocks=true

run-client-rpc:
	@echo "\033[32mrun docker client-rpc\033[0m"; \
	docker run -d \
	--net $(NETWORK) \
	--restart=always \
	-e RUST_LOG=$(RUST_LOG) \
	--name $(prefix)client-rpc \
	-v $(data_path)/wallet:/crypto-chain/wallet \
	-p $(CLIENT_RPC_PORT):26659 \
	$(IMAGE):$(TAG) \
	client-rpc \
	--port=26659 \
	--chain-id=$(CHAIN_ID) \
	--storage-dir=/crypto-chain/wallet \
	--websocket-url=ws://$(prefix)tendermint:26657/websocket \
	--disable-fast-forward

.PHONY: sgx-query chain-abci tendermint client-rpc

START = $(patsubst %, start-%, $(ITEMS_START))
RESTART = $(patsubst %, restart-%, $(ITEMS_START))
STOP = $(patsubst %, stop-%, $(ITEMS_STOP))
REMOVE = $(patsubst %, rm-%, $(ITEMS_STOP))

start-%: %
	@echo "\033[32mstart $(prefix)$<...\033[0m" && docker start $(prefix)$< || echo "start $< failed";
stop-%: %
	@echo "\033[32mstop $(prefix)$<...\033[0m" && docker stop $(prefix)$< || echo "$< does not exist";
restart-%: %
	@echo "\033[32mrestart $(prefix)$<...\033[0m" && docker restart $(prefix)$< || echo "$< does not exist";
rm-%: %
	@echo "\033[32mrm $(prefix)$<...\033[0m" && docker rm -f $(prefix)$< || echo "";

start-all:    $(START)
stop-all:     $(STOP)
rm-all:       $(REMOVE)
restart-all:  $(RESTART)

stop-sgx:
	@echo "\033[32mstop $(prefix)sgx-query...\033[0m" && docker stop $(prefix)sgx-query || echo "sgx-query does not exist or stopped";

stop-chain:
	@echo "\033[32mstop $(prefix)chient-rpc...\033[0m" && docker stop $(prefix)client-rpc || echo "client-rpc does not exist";
	@echo "\033[32mstop $(prefix)tendermint...\033[0m" && docker stop $(prefix)tendermint || echo "tendermint does not exist";
	@echo "\033[32mstop $(prefix)chain-abci...\033[0m" && docker stop $(prefix)chain-abci || echo "chain-abci does not exist";

clean-data:
	docker run -i --rm  \
		-v $(data_path):/data \
		--user root \
		$(IMAGE):$(TAG) \
		bash -c "rm -rf /data/{enclave-storage/*,chain-storage/*,wallet/*}"
	docker run -i --rm \
		-v $(data_path)/tendermint:/tendermint \
		--user root \
		$(IMAGE_TENDERMINT) unsafe_reset_all

rmi:
	docker rmi $(prefix)crypto-sgx:$(TAG) $(prefix)crypto-chain:$(TAG)

clean:
	@echo "\033[32mclean tx-query\033[0m";
	docker run -i --rm \
		-v `pwd`:/chain \
		$(IMAGE_RUST):latest \
		bash -c "cd /chain/chain-tx-enclave/tx-query && . /root/.docker_bashrc && make clean";
	@echo "\033[32mclean tx-validation\033[0m";
	docker run -i --rm \
		-v `pwd`:/chain \
		$(IMAGE_RUST):latest \
		bash -c "cd /chain/chain-tx-enclave/tx-validation && . /root/.docker_bashrc && make clean";
	@echo "\033[32mclean chain\033[0m";
	docker run -i --rm \
		-v `pwd`:/chain \
		--workdir=/chain \
		${IMAGE_RUST}:latest \
		bash -c ". /root/.docker_bashrc && cargo clean"

prepare:    create-path install-sgx-driver init-tendermint
build-sgx:  build-sgx-query build-chain build-sgx-validation
build:      build-chain build-sgx
run-sgx:    create-network run-sgx-query
run-chain:  create-network run-tendermint run-abci run-client-rpc
run:        run-sgx run-chain

help:
	@echo "A makefile based tool to prepare the environment, build binaries, launch a chain cluster \n\
\n\
	USAGE:\n\
		make [OPTIONS] <SUBCOMMAND>\n\
\n\
	OPTIONS:\n\
		data_path=<DATA_PATH>   where the chain data storage, default is /tmp/data\n\
		base_port=<BASE_PORT>   set the base port so that the middleware's port can be \n\
		                        set based on the port, default is 26650\n\
		RUST_LOG=<LOG_LEVEL>    debug | info | warn | error, the log level, default is debug\n\
		chain=<CHAIN_TYPE>      devnet | testnet | mainnet, default is devnet\n\
		prefix=<PREFIX>         default is empty, when create a docker, you can add a prefix on the docker name,\n\
                                it's useful when you want to create a multiple chain node on one host\n\
		sgx_mode=<MODE>         HW | SW, default is HW\n\
		tag=<TAG>               the chain version used in docker image, if not set, it will use\n\
		                        the current git tag or develop if no tag found\n\
		build_mode=<BUILD_MODE> debug | release, default is debug\n\
\n\
	SUBCOMMAND:\n\
		prepare                prepare the environment\n\
		image                  build the docker image\n\
		build                  just build the chain and enclave binaery in docker\n\
		run-sgx                docker run chain-abci and a sgx-query container\n\
		run-chain              docker run chain-abci, tendermint and client-rpc container\n\
		stop-all               docker stop all the container\n\
		start-all              docker start all the container\n\
		restart-all            docker restart all the container\n\
		rm-all                 remove all the docker container\n\
		clean                  clean all the temporary files while compiling\n\
		clean-data             remove all the data in data_path\n\
\n\
	EXAMPLE:\n\
\n\
	make data_path=~/data chain_type=devnet prepare\n\
	make  tag=v0.2.0 image\n\
	make data_path=~/data prefix=node0- base_port=16650 run-sgx\n\
	make data_path=~/data  prefix=node0- base_port=16650 run-chain\n\
	make prefix=node0- rm-all\n\
	make data_path=~/data clean-code\n\
	"