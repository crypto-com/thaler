FROM rust:1.34.2

ARG BINARY=""

ENV RUSTFLAGS "-Ctarget-feature=+aes,+ssse3"
ENV BINARY ${BINARY}

WORKDIR /usr/src/chain

RUN apt-get update -y
RUN apt-get install cmake libgflags-dev -y

COPY . .
COPY docker/chain-preinit/.storage .storage
COPY docker/chain-preinit/.client-rpc-storage .client-rpc-storage
COPY ./docker/wait-for-it.sh /usr/bin/wait-for-it.sh
RUN chmod +x /usr/bin/wait-for-it.sh

RUN if [ "x$BINARY" = "x" ] ; then cargo build ; else cargo build --package ${BINARY} ; fi
RUN mv target/debug/* /usr/bin/

CMD /usr/bin/${BINARY}
STOPSIGNAL SIGTERM
