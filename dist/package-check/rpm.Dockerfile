FROM fedora:45
RUN dnf install -y shadow-utils systemd python3 util-linux && dnf clean all
