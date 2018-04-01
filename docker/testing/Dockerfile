FROM docker.io/ekiden/development:0.1.0-alpha.0

# This is the release of tendermint to pull in.
ENV TM_VERSION 0.13.0
ENV TM_SHA256SUM 36d773d4c2890addc61cc87a72c1e9c21c89516921b0defb0edfebde719b4b85

# Tendermint will be looking for genesis file in /tendermint (unless you change
# `genesis_file` in config.toml). You can put your config.toml and private
# validator file into /tendermint.
#
# The /tendermint/data dir is used by tendermint to store state.
ENV DATA_ROOT /tendermint
ENV TMHOME $DATA_ROOT

# Set user right away for determinism
RUN adduser --system --group tmuser

# Create directory for persistence and give our user ownership
RUN mkdir -p $DATA_ROOT && \
    chown -R tmuser:tmuser $DATA_ROOT

# jq and curl used for extracting `pub_key` from private validator while
# deploying tendermint with Kubernetes. It is nice to have bash so the users
# could execute bash commands.
RUN apt-get install -y jq

RUN wget https://s3-us-west-2.amazonaws.com/tendermint/binaries/tendermint/v${TM_VERSION}/tendermint_${TM_VERSION}_linux_amd64.zip && \
    echo "${TM_SHA256SUM}  tendermint_${TM_VERSION}_linux_amd64.zip" | sha256sum -c && \
    unzip -d /bin tendermint_${TM_VERSION}_linux_amd64.zip && \
    rm -f tendermint_${TM_VERSION}_linux_amd64.zip

# Leave $DATA_ROOT in the ephemeral filesystem so that we start tests with a clean state.

# Don't expose services from testing instance.
