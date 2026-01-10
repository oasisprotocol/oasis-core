FROM ubuntu:24.04

ARG MODE=dcap

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -qq curl lsb-release gpg

ADD intel-sgx-deb.asc /etc/apt/trusted.gpg.d

RUN echo "deb https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/intel-sgx.list

RUN if [ "$MODE" = "dcap" ] ; then \
    apt-get update -qq && apt-get install -qq sgx-aesm-service libsgx-aesm-ecdsa-plugin libsgx-aesm-quote-ex-plugin libsgx-dcap-default-qpl && \
    sed -i 's|"pccs_url": ".*"|"pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/"|' /etc/sgx_default_qcnl.conf; \
    elif [ "$MODE" = "epid" ]; then \
    apt-get update -qq && apt-get install -qq sgx-aesm-service libsgx-aesm-launch-plugin libsgx-aesm-epid-plugin; \
    else \
    echo "Invalid mode: $MODE" && exit 1; \
    fi

ENV AESM_PATH=/opt/intel/sgx-aesm-service/aesm
ENV LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm

WORKDIR /opt/intel/sgx-aesm-service/aesm

ENTRYPOINT ["/opt/intel/sgx-aesm-service/aesm/aesm_service", "--no-daemon", "--no-syslog"]
