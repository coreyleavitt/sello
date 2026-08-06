# Containerfile — sello-owned libsodium test image (RFC-001 slice 10).
#
# Minimal layer on top of the base Nim toolchain image, adding only the
# libsodium development headers/library needed to compile and link
# src/sello/private/backend_sodium.nim under -d:selloLibsodium.
#
# Containerfile.amox is amoxtli's unrelated sandbox image (rust/go/node/
# openssl, for a different project entirely) -- do not confuse the two.
# This Containerfile is sello's own build infrastructure, used only for
# `nimble testLibsodium`. `nimble test` and `nimble ct` need neither this
# image nor network access.
FROM ghcr.io/coreyleavitt/nim:2.2.10

RUN zypper --non-interactive install --no-recommends libsodium-devel \
    && zypper clean -a \
    && rm -rf /var/cache/zypp/*
