#!/usr/bin/env bash
# scripts/lib/tier-summary.sh — end-of-run validation-tier visibility
# (round-3 fix batch B, finding B6). `source`d by scripts/test.sh and
# scripts/test-libsodium.sh (shared, not duplicated, per this project's
# established scripts/lib/ convention -- round-2 finding 25's same
# reasoning) after a successful podman run, so a caller reading a green
# `scripts/test.sh` output can tell AT A GLANCE which of CLAUDE.md's
# validation-bar tiers this one invocation actually covered, vs. which
# are separate scripts it never touched -- rather than having to already
# know the project's test layout to know what "green" does and does not
# mean.
#
# Reads `unit_test_files`/`skipped_property_files` (populated by
# scripts/lib/unit-test-files.sh, already sourced by both callers before
# this file) -- not re-derived, so the summary can never drift from the
# actual file list a run compiled.
print_tier_summary() {
  local invoked_as="$1" # e.g. "scripts/test.sh" or "scripts/test-libsodium.sh (-d:selloLibsodium)"
  # Optional second argument (RFC-005 slice 14): overrides the default
  # "nelli not fetched" reason text below. scripts/test-libsodium.sh
  # passes its own reason -- it ALWAYS excludes the standalone
  # test_properties_*.nim files from its own compiled set (a scope
  # decision, see that script's own header comment), independent of
  # whether nelli is actually fetched (it always is, under that
  # script's SELLO_IN_CONTAINER=1 body), so the default wording here
  # would be actively misleading for that caller.
  local property_skip_reason="${2:-nelli not fetched (${#skipped_property_files[@]} file(s); run: milpa fetch --features nelli)}"

  local property_count=0 f
  for f in "${unit_test_files[@]}"; do
    case "$f" in
      tests/unit/test_properties_*.nim) property_count=$((property_count + 1)) ;;
    esac
  done

  local property_status
  if [ "${#skipped_property_files[@]}" -gt 0 ]; then
    property_status="SKIPPED -- $property_skip_reason"
  else
    property_status="RAN ($property_count file(s))"
  fi

  local other_count=$((${#unit_test_files[@]} - property_count))

  echo ""
  echo "======================================================================="
  echo "Validation tier summary -- $invoked_as"
  echo "======================================================================="
  echo "  unit + vectors (RFC 8032/7748 KATs, Wycheproof adversarial corpora,"
  echo "  libsodium differential suite, facade/CT smoke):    RAN ($other_count file(s))"
  echo "  property-based (test_properties_*.nim via nelli): $property_status"
  echo "  -----------------------------------------------------------------"
  echo "  NOT exercised by this invocation -- separate scripts, run directly:"
  echo "    fuzz (coverage-guided, tests/fuzz/):        scripts/fuzz.sh"
  echo "    mutation (curated catalog, tests/mutation/): scripts/mutation.sh"
  echo "    dudect timing harness (tests/ct/):           scripts/ct.sh"
  echo "    Z3 machine-checked proof (tests/verify/):    scripts/bmc.sh"
  echo "======================================================================="
}
