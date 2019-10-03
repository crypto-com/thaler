FROM rust:1.38.0

ENV RUSTFLAGS "-Ctarget-feature=+aes,+ssse3"

WORKDIR /usr/src/chain

# RUN echo "deb http://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/ ./" >> /etc/apt/sources.list
# RUN wget https://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/Release.key -O- | apt-key add
RUN apt-get update -y
RUN apt-get install cmake libgflags-dev libzmq3-dev pkg-config -y

COPY . .
COPY integration-tests/docker/chain/wallet-storage ./wallet-storage
COPY integration-tests/docker/wait-for-it.sh /usr/bin/wait-for-it.sh

RUN cargo build
RUN mv target/debug/chain-abci /usr/bin/chain-abci
RUN mv target/debug/client-rpc /usr/bin/client-rpc

STOPSIGNAL SIGTERM
