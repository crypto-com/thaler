FROM alpine:3.9.4
LABEL maintainer="hello@tendermint.com"
LABEL maintainer="calvin@crypto.com"

ARG VERSION

# WITHFEE|ZEROFEE
ENV FEE_SCHEMA="WITHFEE"

# Tendermint will be looking for the genesis file in /tendermint/config/genesis.json
# (unless you change `genesis_file` in config.toml). You can put your config.toml and
# private validator file into /tendermint/config.
#
# The /tendermint/data dir is used by tendermint to store state.
ENV TMHOME /tendermint

# OS environment setup
# Set user right away for determinism, create directory for persistence and give our user ownership
# jq and curl used for extracting `pub_key` from private validator while
# deploying tendermint with Kubernetes. It is nice to have bash so the users
# could execute bash commands.
RUN apk update && \
    apk upgrade && \
    apk --no-cache add curl jq bash && \
    addgroup tmuser && \
    adduser -S -G tmuser tmuser -h "$TMHOME"

# Download and install Tendermint
RUN echo "Installing Tendermint ${VERSION}"
RUN curl -LO https://github.com/tendermint/tendermint/releases/download/v${VERSION}/tendermint_v${VERSION}_linux_amd64.zip
RUN unzip tendermint_v${VERSION}_linux_amd64.zip -d /usr/bin/
RUN rm tendermint_v${VERSION}_linux_amd64.zip

WORKDIR /app

COPY ./integration-tests/docker/tendermint ./ 

# p2p and rpc port
EXPOSE 26656 26657

CMD ["/app/bin/entrypoint.sh"]
STOPSIGNAL SIGTERM
