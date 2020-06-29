From ubuntu:18.04

RUN apt update && apt install -y \
  make \
  libzmq3-dev \
  libssl1.1 \
  curl \
  wget \
  gnupg \
  libcurl4-openssl-dev \
  libprotobuf-dev \
  libssl-dev \
  libgflags-dev \
  libprotobuf10 && \
  rm -rf /var/lib/apt/lists/*

arg BUILD_MODE

# copy the binary file
COPY ./target/${BUILD_MODE}/client-cli /usr/local/bin/
COPY ./target/${BUILD_MODE}/chain-abci /usr/local/bin/
COPY ./target/${BUILD_MODE}/client-rpc /usr/local/bin/
COPY ./target/${BUILD_MODE}/dev-utils /usr/local/bin/
# copy sgx binary file
COPY ./target/${BUILD_MODE}/tx-query2-app-runner /usr/local/bin
COPY ./target/${BUILD_MODE}/tx-query2-enclave-app.sig /usr/local/bin
COPY ./target/${BUILD_MODE}/tx-query2-enclave-app.sgxs /usr/local/bin
COPY ./target/${BUILD_MODE}/ra-sp-server /usr/local/bin
COPY ./target/${BUILD_MODE}/tx_validation_enclave.signed.so /usr/local/bin
# copy scripts
COPY ./docker/wait-for-it.sh /usr/local/bin
COPY ci-scripts/run_tx_query_next.sh /usr/local/bin
COPY ci-scripts/run_chain_abci.sh /usr/local/bin

# install sgx enclave pws 2.9
RUN mkdir -p /opt/intel && \
  cd /opt/intel && \
  set -eux; \
  echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list; \
  wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -; \
  apt-get update; \
  apt-get install -y libsgx-launch libsgx-epid libsgx-quote-ex libsgx-urts libsgx-uae-service; \
  rm -rf /var/lib/apt/lists/*

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
