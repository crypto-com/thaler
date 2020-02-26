From ubuntu:18.04

RUN apt-get update && apt-get install -y \
    make \
    libzmq3-dev \
    libssl1.1 \
    curl \
    libprotobuf-dev \
    libssl-dev && \
    rm -rf /var/lib/apt/lists/*

arg BUILD_MODE

# copy the binary file
COPY ./target/${BUILD_MODE}/client-cli /usr/local/bin/
COPY ./target/${BUILD_MODE}/chain-abci /usr/local/bin/
COPY ./target/${BUILD_MODE}/client-rpc /usr/local/bin/
COPY ./target/${BUILD_MODE}/dev-utils /usr/local/bin/
# copy sgx binary file
COPY ./target/${BUILD_MODE}/tx-query-app /usr/local/bin
COPY ./target/${BUILD_MODE}/tx_query_enclave.signed.so /usr/local/bin
COPY ./target/${BUILD_MODE}/tx_validation_enclave.signed.so /usr/local/bin
# copy scripts
COPY ./docker/wait-for-it.sh /usr/local/bin
COPY ci-scripts/run_tx_query.sh /usr/local/bin
COPY ci-scripts/run_chain_abci.sh /usr/local/bin

# install sgx enclave pws
ARG SGX_ENCLAVE=https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/libsgx-enclave-common_2.7.101.3-bionic1_amd64.deb
# TODO
# update PSW to 2.8
# ARG SGX_ENCLAVE=https://download.01.org/intel-sgx/sgx-linux/2.8/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-enclave-common/libsgx-enclave-common_2.8.100.3-bionic1_amd64.deb

RUN mkdir -p /opt/intel && \
    cd /opt/intel && \
    set -eux; \
    curl -L  ${SGX_ENCLAVE} -o common.deb &&\
    dpkg -i common.deb; rm common.deb;

WORKDIR /usr/local/bin
STOPSIGNAL SIGTERM

ENV RUST_LOG=info
ENV TX_ENCLAVE_STORAGE=/crypto-chain/enclave-storage

ENV SGX_MODE=${SGX_MODE}
ENV NETWORK_ID=${NETWORK_ID}

ENV APP_PORT_VALIDATION=26650
ENV APP_PORT_QUERY=26651
ENV TX_QUERY_TIMEOUT=10
ENV TX_VALIDATION_CONN=${TX_VALIDATION_CONN}
