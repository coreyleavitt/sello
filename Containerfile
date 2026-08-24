# Containerfile — sello-owned dev image ("sello-dev": RFC-001 slice 10 +
# B4b), covering every RFC-005 matrix/gate that needs more than the base
# Nim toolchain image. Consolidated in RFC-005 slice 7 ("Image
# consolidation") into the single package set the *whole* RFC needs, so
# later Phase 1-3 slices (8-23) land their own job wiring without ever
# touching this file again for a package addition -- one pin event, not
# one per consuming slice (per that slice's own text).
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
#   - gcc-32bit / glibc-devel-32bit / libstdc++6-32bit: 32-bit multilib --
#     `gcc -m32` support for slice 10's `--cpu:i386` job (identity canary:
#     pointers are 4 bytes). openSUSE's 32-bit compat packages, verified by
#     `zypper search -s` against this exact base image (RFC-005 slice 7);
#     zypper pulls in the matching `gcc16-32bit`/`glibc-32bit` transitively.
#   - valgrind: slice 19's Valgrind/MSan go-no-go for the taint CT harness.
#   - lcov: slice 17's coverage ratchet (`gcov`/`lcov` report generation).
#     Note: this one drags in a large perl (DateTime et al.) dependency
#     chain (~82 new packages transitively as of slice 7's verification) --
#     accepted, since lcov itself is the tool slice 17 needs and there is
#     no lighter-weight substitute in this repo's zypper base.
#   - cross-s390x-gcc16: slice 25's nightly s390x cross-compile job.
#     Version-numbered per openSUSE's per-gcc-major cross-compiler naming
#     (`cross-s390x-gcc<N>`) -- `gcc16` chosen to match this base image's
#     own native `gcc16` package (`gcc --version` -> GCC 16.x as of slice
#     7's verification), so the cross and native toolchains share a major
#     version. Re-verify this pairing if the base image's own gcc major
#     version ever moves.
#   - qemu-linux-user: openSUSE's package name for user-mode QEMU
#     (`qemu-user-static` in Debian/Ubuntu naming, which does not exist
#     under that name here -- verified via `zypper search`, RFC-005 slice
#     7) -- runs the s390x cross-compiled binaries from slice 25's nightly
#     job under emulation.
#
# NOT added, because both are already present in the base
# ghcr.io/coreyleavitt/nim:2.2.10 image (verified via `which`/`rpm -qa`
# inside it, RFC-005 slice 7 -- do not re-add if a future base-image bump
# ever drops them; re-verify instead):
#   - binutils (objdump/nm/etc, slice 23's disasm gate) -- already
#     installed as a base-image dependency of its own gcc toolchain.
#   - clang (slices 8/9/19/22's four consumers: clang-backend job,
#     ASan/UBSan job, taint CT harness's gcc+clang pair, taint CI) --
#     already installed in the base image (`clang`/`clang22` packages).
#     The RFC's round-2 finding ("clang ... missing from the list") was
#     written against an assumption that did not hold empirically at
#     slice-7 verification time; recorded here rather than silently
#     dropped, since a future base-image change could reintroduce the gap.
#
# One image, one Containerfile, covering every matrix -- avoids
# maintaining a second near-duplicate layer for the sake of a name. The
# RFC's own two-image split (lean core / heavy gates) stays pre-authorized
# if a future slice's pull-cost measurement ever breaks the wall-clock
# budget (see docs/rfc-005-validation-infra.handoff.md's slice 7 entry for
# the sizing measurement this cut against as of this slice).
#
# Containerfile.amox is amoxtli's unrelated sandbox image (rust/go/node/
# openssl, for a different project entirely) -- do not confuse the two.
# This Containerfile is sello's own build infrastructure, used by
# scripts/test-libsodium.sh and scripts/bmc.sh today (pull-by-digest of
# the published ghcr.io/coreyleavitt/sello-dev image as of RFC-005 slice
# 7, with a local-build escape hatch -- see those scripts' own header
# comments) and by later RFC-005 Phase 1-3 job wiring as it lands.
# scripts/test.sh, scripts/ct.sh, and scripts/fuzz.sh need neither this
# image nor network access (fuzz.nim, unlike symex.nim, never imports z3 --
# confirmed in the B4a summary, docs/rfc-001-signing.handoff.md).
#
# FROM is pinned by digest, not the `2.2.10` tag (RFC-005 Part B: a mutable
# tag is "trust our transcripts" one layer down -- same rule as every
# workflow `container:` field; digest recorded in
# scripts/lib/image-pins.txt's base-image section, kept in sync with that
# file's own copy by hand at repin time). RFC-005 slice 7 found this tag
# genuinely move mid-session while verifying this Containerfile (the
# `2.2.10` tag's own linux/amd64 sub-manifest digest changed during a
# single work session, with no action against this repo) -- a live,
# unplanned demonstration of exactly the risk this pin exists to close.
FROM ghcr.io/coreyleavitt/nim@sha256:cd4708fb29d16ec4256a0bdcf8a4873b1f5a7a7200e32890ed52d5893227e780

RUN zypper --non-interactive install --no-recommends \
        libsodium-devel z3-devel \
        gcc-32bit glibc-devel-32bit libstdc++6-32bit \
        valgrind lcov \
        cross-s390x-gcc16 \
        qemu-linux-user \
    && zypper clean -a \
    && rm -rf /var/cache/zypp/*
