# CLEAR_LINUX_BASE and CLEAR_LINUX_VERSION can be used to make the build
# reproducible by choosing an image by its hash and installing an OS version
# with --version=:
# CLEAR_LINUX_BASE=clearlinux@sha256:b8e5d3b2576eb6d868f8d52e401f678c873264d349e469637f98ee2adf7b33d4
# CLEAR_LINUX_VERSION="--version=29970"
#
# This is used on release branches before tagging a stable version.
# The master branch defaults to using the latest Clear Linux.
ARG CLEAR_LINUX_BASE=clearlinux/golang:latest

FROM ${CLEAR_LINUX_BASE} as builder

ARG CLEAR_LINUX_VERSION=

RUN swupd update --no-boot-update ${CLEAR_LINUX_VERSION}
RUN swupd bundle-add make ${CLEAR_LINUX_VERSION}
RUN mkdir /install_root \
    && swupd os-install \
    ${CLEAR_LINUX_VERSION} \
    --path /install_root \
    --statedir /swupd-state \
    --bundles=os-core \
    --no-boot-update \
    && rm -rf /install_root/var/lib/swupd/*

ARG DIR=/go/src/build
WORKDIR $DIR
ADD . $DIR

ENV GO111MODULE=on GOFLAGS=-mod=vendor
RUN make BUILD_DIRS=cri-resmgr-agent

FROM scratch as final
ARG DIR=/go/src/build
COPY --from=builder /install_root /
COPY --from=builder $DIR/bin/cri-resmgr-agent /bin/cri-resmgr-agent
ENTRYPOINT ["/bin/cri-resmgr-agent"]
