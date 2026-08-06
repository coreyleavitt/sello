# sello config.nims
#
# Nim reads nim.cfg AND config.nims side by side; milpa only generates/owns
# nim.cfg (the --path entries for src/ and each resolved dep in _deps/,
# rewritten wholesale on every `milpa fetch`/`milpa clean`). The two flags
# below are project-standing build settings, not dependency-resolution
# state, so they live here instead — this file is untouched by milpa and
# survives every fetch/clean cycle.

switch("mm", "orc")
switch("outdir", "build")
