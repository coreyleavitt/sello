# Containerfile — sello-owned dev image ("sello-dev": RFC-001 slice 10 +
# B4b), covering the two matrices that need more than the base Nim
# toolchain: the libsodium adapter and the Z3-backed BMC/symex proof.
#
# Layer on top of the base Nim toolchain image, adding:
#   - libsodium-devel: headers/library needed to compile and link
#     src/sello/private/backend_sodium.nim under -d:selloLibsodium
#     (scripts/test-libsodium.sh).
#   - z3-devel: the Z3 shared library COREY'S proptest library's
#     `proptest/symex` module dlopens (via its `nim-z3`/softlink deps) --
#     needed only by tests/verify/ (scripts/bmc.sh). Mirrors proptest's own
#     scripts/Containerfile dev-image pattern (z3-devel on the same Nim
#     base image); see docs/symex/ in the proptest repo for why symex needs
#     it and fuzz.nim does not (fuzz has no z3 import at all).
#
# One image, one Containerfile, covering both matrices -- avoids
# maintaining a second near-duplicate layer for the sake of a name.
#
# Containerfile.amox is amoxtli's unrelated sandbox image (rust/go/node/
# openssl, for a different project entirely) -- do not confuse the two.
# This Containerfile is sello's own build infrastructure, used only by
# scripts/test-libsodium.sh and scripts/bmc.sh. scripts/test.sh, scripts/ct.sh,
# and scripts/fuzz.sh need neither this image nor network access (fuzz.nim,
# unlike symex.nim, never imports z3 -- confirmed in the B4a summary,
# docs/rfc-001-signing.handoff.md).
FROM ghcr.io/coreyleavitt/nim:2.2.10

RUN zypper --non-interactive install --no-recommends libsodium-devel z3-devel \
    && zypper clean -a \
    && rm -rf /var/cache/zypp/*
