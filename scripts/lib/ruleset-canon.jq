# scripts/lib/ruleset-canon.jq — RFC-005 slice 4: shared ruleset JSON
# canonicalization, used by both scripts/ruleset-apply.sh (building the PUT/
# POST/PATCH body) and scripts/ruleset-sync-check.sh (the ruleset-sync CI
# check's live-vs-committed comparison). One filter file, two consumers —
# the same "shared parser, not two independently-typed-out copies"
# precedent as scripts/lib/gates.sh (round-2 finding 25).
#
# Two entry points:
#
#   set_required_checks($checks) — splices a generated array of
#   {"context": name} objects (built from scripts/lib/gates.txt via
#   scripts/lib/gates.sh's load_gates(), never hand-transcribed — see
#   ruleset-apply.sh/ruleset-sync-check.sh) into the required_status_checks
#   rule's parameters.required_status_checks field, for every rule of that
#   type present (today, at most one, on the "main" ruleset only). Applied
#   to the COMMITTED json before both applying (PUT/PATCH body) and
#   diffing (the expected side of ruleset-sync) — the committed
#   .github/rulesets/main.json file's own required_status_checks array is
#   therefore never read literally; it exists only as a placeholder shape,
#   and gates.txt is the one source of truth for the name list (RFC-005
#   Part B's Rulesets paragraph: "the required-check array is generated,
#   never hand-written").
#
#   normalize — strips fields the GitHub API attaches to a live ruleset
#   that the committed JSON never carries (id, node_id, timestamps, source
#   metadata, _links, current_user_can_bypass — all live-response-only,
#   not policy), and sorts every order-insensitive array (rules by .type,
#   required_status_checks entries by .context, bypass_actors by their
#   identity tuple, ref_name include/exclude lists) so a live response
#   GitHub happens to return in different array order from the committed
#   file's own order is never reported as spurious drift. Deep object-key
#   order is handled separately by the caller piping the result through
#   `jq -S`.
#
# Only ruleset-sync's "read live, normalize, compare byte-for-byte against
# normalize(splice(committed))" comparison, plus ruleset-apply's
# "splice(committed), PUT/PATCH" construction, ever touch this file — no
# other script needs the ruleset JSON shape.
#
# Empirical GitHub API finding (verified live against a disposable probe
# ruleset before this file was written, not assumed): a rule whose
# `parameters` equals that rule type's default/empty shape (`deletion`,
# `non_fast_forward`, and `update` with `update_allows_fetch_and_merge`
# left at its `false` default) is echoed back on GET/POST with NO
# `parameters` key at all, not `"parameters": {}` — so the committed JSON
# files omit `parameters` for those three rule types (matching what the
# API actually returns) and `normalize` still strips an empty/absent
# `parameters` key uniformly below, defensively, in case a future rule
# addition reintroduces one.

def strip_empty_parameters:
  if (has("parameters")) and (.parameters == null or .parameters == {}) then
    del(.parameters)
  else
    .
  end;

def set_required_checks($checks):
  .rules |= map(
    if .type == "required_status_checks" then
      .parameters.required_status_checks = $checks
    else
      .
    end
  );

def normalize:
  del(.id, .node_id, .created_at, .updated_at, .source_type, .source, .current_user_can_bypass, ._links)
  | .rules |= (
      map(
        (if .type == "required_status_checks" and (.parameters.required_status_checks? != null) then
          .parameters.required_status_checks |= sort_by(.context)
        else
          .
        end)
        | strip_empty_parameters
      )
      | sort_by(.type)
    )
  | .bypass_actors |= (
      (. // [])
      | sort_by([.actor_type, (.actor_id // 0), (.bypass_mode // "always")])
    )
  | (if (.conditions.ref_name?) then
       .conditions.ref_name.include |= ((. // []) | sort)
       | .conditions.ref_name.exclude |= ((. // []) | sort)
     else . end);
