# Build
FROM rust:1.35.0 as rust-builder

ENV RUSTFLAGS "-Ctarget-feature=+aes,+ssse3"

WORKDIR /usr/src/chain

RUN apt-get update -y
RUN apt-get install cmake libgflags-dev -y

COPY . .

RUN cargo build --release
RUN mkdir /usr/bin/chain
RUN mv target/release/chain-abci /usr/bin/chain/chain-abci
RUN mv target/release/client-rpc /usr/bin/chain/client-rpc

# Image
FROM rust:1.35.0-slim

WORKDIR /usr/src/chain

COPY docker/wait-for-it.sh /usr/bin/wait-for-it.sh
RUN chmod +x /usr/bin/wait-for-it.sh

COPY docker/chain-preinit/.storage .storage
COPY docker/chain-preinit/.client-rpc-storage .client-rpc-storage
COPY --from=rust-builder /usr/bin/chain/* /usr/bin/

STOPSIGNAL SIGTERM
