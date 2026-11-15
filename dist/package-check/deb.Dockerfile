FROM ubuntu:24.04
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       adduser init-system-helpers systemd python3 util-linux \
    && rm -rf /var/lib/apt/lists/*
