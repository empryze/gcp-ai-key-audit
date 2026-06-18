#!/usr/bin/env bash
#
# discovery_test.sh — unit tests for project-discovery logic.
#
# COVERS:   the three --discovery backends (flat / recursive / asset), including
#           folder-in-folder nesting and Cloud Asset JSON parsing, using a stubbed
#           gcloud. This guards the tool's most important and most easily-broken
#           behavior: completely enumerating a folder hierarchy.
# DOES NOT: hit real GCP, exercise key classification, or validate IAM/permissions.
#           A green run means the discovery algorithm is correct, not that a live
#           scan is complete (see the Limitations section of the README).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Source the tool as a library (defines functions, skips main).
# shellcheck disable=SC1091  # path resolved at runtime; not followed by the linter
GCAUDIT_LIB_ONLY=1 source "$SCRIPT_DIR/../gcp-ai-key-audit.sh"

# Stubbed org:
#   org 999
#     ├─ projects: top-a, top-b
#     ├─ folders/100 ── projects: p100-x ── folders/110 ── projects: p110-deep
#     └─ folders/200 ── projects: p200-y
# shellcheck disable=SC2317  # gc() is called indirectly by the sourced discover_* functions
gc() {
  local a="$*"
  case "$a" in
    *"projects list"*"parent.id=999 AND parent.type=organization"*) printf 'top-a\ntop-b\n' ;;
    *"projects list"*"parent.id=100 AND parent.type=folder"*)        printf 'p100-x\n' ;;
    *"projects list"*"parent.id=110 AND parent.type=folder"*)        printf 'p110-deep\n' ;;
    *"projects list"*"parent.id=200 AND parent.type=folder"*)        printf 'p200-y\n' ;;
    *"folders list --organization=999"*)                             printf 'folders/100\nfolders/200\n' ;;
    *"folders list --folder=100"*)                                   printf 'folders/110\n' ;;
    *"folders list --folder=110"*)                                   : ;;
    *"folders list --folder=200"*)                                   : ;;
    *"asset search-all-resources"*) cat <<'JSON'
[{"name":"//cloudresourcemanager.googleapis.com/projects/376456379761","additionalAttributes":{"projectId":"asset-proj-a"}},
 {"name":"//cloudresourcemanager.googleapis.com/projects/290555900214"}]
JSON
;;
    *) : ;;
  esac
}

fail=0
assert_eq() { # label expected actual
  if [[ "$2" == "$3" ]]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1"; echo "       expected: [$2]"; echo "       actual:   [$3]"; fail=1
  fi
}

assert_eq "flat: direct org children only" \
  "top-a top-b" \
  "$(discover_flat 999 | sort | paste -sd' ' -)"

assert_eq "recursive: reaches folder-in-folder projects" \
  "p100-x p110-deep p200-y top-a top-b" \
  "$(discover_recursive 999 | sort | paste -sd' ' -)"

assert_eq "asset: projectId when present, else project number" \
  "290555900214 asset-proj-a" \
  "$(discover_asset 999 | sort | paste -sd' ' -)"

echo
if [[ $fail -eq 0 ]]; then echo "All discovery tests passed."; else echo "Some tests FAILED."; fi
exit $fail
