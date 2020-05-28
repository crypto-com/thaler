ARG SGX_MODE=HW
ARG NETWORK_ID=AB

FROM ubuntu:18.04 AS RUNTIME_BASE
LABEL maintainer="blockchain@crypto.com"

RUN set -e; \
    apt-get update; \
    apt-get install -y wget libssl-dev libcurl4-openssl-dev libprotobuf-dev gnupg; \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list; \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -; \
    apt-get update; \
    apt-get install -y libzmq3-dev libssl1.1 libprotobuf10 libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex; \
    rm -rf /var/lib/apt/lists/*

COPY --from=tendermint/tendermint:v0.33.4 /usr/bin/tendermint /usr/bin/tendermint

FROM baiduxlab/sgx-rust:1804-1.1.2 AS BUILDER_BASE
LABEL maintainer="blockchain@crypto.com"

ARG SGX_MODE
ARG NETWORK_ID

ENV SGX_SDK=/opt/sgxsdk
ENV PATH=/root/.cargo/bin:/root/.local/bin:$PATH
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS "-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
ENV SGX_MODE=$SGX_MODE
ENV NETWORK_ID=$NETWORK_ID

RUN set -e; \
    apt-get update; \
    apt-get install -y \
      cmake \
      libgflags-dev \
      libzmq3-dev \
      pkg-config \
      clang; \
    rm -rf /var/lib/apt/lists/*

# fortanix environment
ENV CFLAGS "-gz=none"
RUN set -e; \
    rustup target add x86_64-fortanix-unknown-sgx; \
    cargo install fortanix-sgx-tools sgxs-tools cargo-crate-type

COPY --from=tendermint/tendermint:v0.33.4 /usr/bin/tendermint /usr/bin/tendermint

FROM BUILDER_BASE AS TEST
LABEL maintainer="blockchain@crypto.com"

ARG SGX_MODE
ARG NETWORK_ID

ENV SGX_MODE=$SGX_MODE
ENV NETWORK_ID=$NETWORK_ID

# install python3.8, nodejs
RUN set -e; \
    apt-get update; \
    apt-get install -y software-properties-common; \
    echo "deb http://ppa.launchpad.net/deadsnakes/ppa/ubuntu bionic main" | tee -a /etc/apt/sources.list; \
    echo "deb-src http://ppa.launchpad.net/deadsnakes/ppa/ubuntu bionic main" | tee -a /etc/apt/sources.list; \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F23C5A6CF475977595C89F51BA6932366A755776; \
    # add-apt-repository -y ppa:deadsnakes/ppa; \
    apt-get install -y python3.8 python3-distutils; \
    curl -sL https://deb.nodesource.com/setup_10.x | bash; \
    apt-get install -y nodejs; \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1; \
    apt-get purge --auto-remove -y software-properties-common; \
    rm -r /var/lib/apt/lists/*

FROM BUILDER_BASE AS BUILDER
LABEL maintainer="blockchain@crypto.com"

ARG SGX_MODE
ARG NETWORK_ID
ARG BUILD_PROFILE=release
ARG BUILD_MODE=sgx

ENV SGX_MODE=$SGX_MODE
ENV NETWORK_ID=$NETWORK_ID
ENV BUILD_PROFILE=$BUILD_PROFILE
ENV BUILD_MODE=$BUILD_MODE

COPY . /src 
WORKDIR /src
RUN set -e; \
    ./docker/build.sh; \
    mkdir /output; \
    for bin in \
      chain-abci \
      client-cli \
      client-rpc \
      dev-utils \
      tx-validation-app \
      tx-query-app \
      tx_query_enclave.signed.so \
      tx_validation_enclave.signed.so ; \
    do mv "./target/${BUILD_PROFILE}/${bin}" /output; done; \
    cargo clean;

FROM RUNTIME_BASE

COPY --from=BUILDER /output/. /crypto-chain
ENV PATH=/crypto-chain:$PATH
WORKDIR /crypto-chain
