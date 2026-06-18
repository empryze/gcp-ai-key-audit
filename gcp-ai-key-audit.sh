#!/usr/bin/env bash
#
# gcp-ai-key-audit — find API keys that can actually be abused to run generative AI on your bill.
#
# v1.2.0 — pluggable project discovery for orgs with folders:
#            --discovery recursive  walk the folder tree to any depth (default; real-time,
#                                   needs resourcemanager.folders.list)
#            --discovery asset      Cloud Asset search-all-resources (one call; needs the
#                                   Cloud Asset API enabled + roles/cloudasset.viewer)
#            --discovery flat       direct org children only (fast, MISSES folder-nested)
#
# Risk model:
#   Vertex / Agent Platform (aiplatform.googleapis.com) via an API key REQUIRES an
#   authorization key (bound to a service account); a standard key cannot reach it.
#   The Gemini API (generativelanguage.googleapis.com) still accepts standard keys, but
#   Google rejects UNRESTRICTED standard keys from 2026-06-19 and ALL standard keys from 2026-09.
#     - authorization key (SA-bound) + unrestricted/AI-scoped + AI enabled = CRITICAL
#     - standard key + Gemini enabled + unrestricted                       = MEDIUM (time-bound)
#     - standard key, over-broad scope (cannot reach Vertex)               = MEDIUM (hygiene)
#     - any broad key with no effective application restriction            = LOW (hygiene)
#
# Requires: gcloud (authenticated), jq.  Optional: coreutils timeout.
#
set -uo pipefail

VERSION="1.2.0"
PROG="${0##*/}"

# ----- defaults -------------------------------------------------------------
DANGEROUS_APIS="generativelanguage.googleapis.com,aiplatform.googleapis.com"
GEMINI_API="generativelanguage.googleapis.com"
GEMINI_UNRESTRICTED_DEADLINE="2026-06-19"
GEMINI_STANDARD_DEADLINE="2026-09"
FORMAT="text"; OUTPUT=""; ORG_ID=""; PROJECTS=(); PROJECTS_FILE=""
DISCOVERY="recursive"
FAIL_ON_CRITICAL=0; VERBOSE=0; NO_COLOR=0
GCLOUD_TIMEOUT="${GCLOUD_TIMEOUT:-60}"; QUIET_PROGRESS=0
GCAUDIT_HAVE_TIMEOUT=""

US=$'\037'; FINDINGS=(); CRITICAL_COUNT=0; MEDIUM_COUNT=0

# ===== function definitions =================================================
usage() {
  cat <<EOF
$PROG v$VERSION — audit GCP projects for API keys that can abuse generative AI

USAGE: $PROG [scope] [options]

SCOPE (choose one; defaults to the active gcloud project):
  --org ORG_ID                 Audit projects in an organization (see --discovery)
  --project ID                 A single project (repeatable)
  --projects-file FILE         Project IDs, one per line

DISCOVERY (only with --org; default: recursive):
  --discovery recursive        Walk the folder tree to any depth (real-time;
                               needs resourcemanager.folders.list)
  --discovery asset            Cloud Asset search-all-resources (one call; needs
                               cloudasset.googleapis.com + roles/cloudasset.viewer)
  --discovery flat             Direct org children only (fast; MISSES folder-nested)

OPTIONS:
  --apis LIST                  Comma-separated dangerous APIs (default: $DANGEROUS_APIS)
  --format text|csv|json       Output format (default: text)
  --output FILE                Write to FILE instead of stdout
  --timeout SECONDS            Max seconds per gcloud call (default: 60; 0 = none)
  --fail-on-critical           Exit 2 if any CRITICAL finding (CI gating)
  --verbose                    Also report clean projects/keys
  --quiet-progress             Suppress per-project progress on stderr
  --no-color                   Disable colored output
  -h, --help / --version
EOF
}

die() { echo "$PROG: $*" >&2; exit 3; }
progress() { [[ $QUIET_PROGRESS -eq 0 ]] && echo "$*" >&2 || true; }

# Non-interactive, timeout-guarded gcloud. Reads GCLOUD_TIMEOUT at call time.
gc() {
  if [[ -n "$GCAUDIT_HAVE_TIMEOUT" && "$GCLOUD_TIMEOUT" != "0" ]]; then
    timeout "$GCLOUD_TIMEOUT" gcloud --quiet "$@" </dev/null
  else
    gcloud --quiet "$@" </dev/null
  fi
}

csv_escape() { printf '"%s"' "${1//\"/\"\"}"; }
json_escape() {
  local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}; printf '%s' "$s"
}
add_finding() {
  FINDINGS+=("$1${US}$2${US}$3${US}$4${US}$5${US}$6${US}$7")
  case "$2" in CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT+1));; MEDIUM) MEDIUM_COUNT=$((MEDIUM_COUNT+1));; esac
}
contains() { grep -qF "$2" <<<"$1"; }

# ----- discovery backends ---------------------------------------------------
discover_flat() {  # ORG -> projectIds of direct org children only
  gc projects list --filter="parent.id=$1 AND parent.type=organization" \
     --format="value(projectId)" 2>/dev/null
}

discover_recursive() {  # ORG -> projectIds at any depth (BFS over folders)
  local org="$1"
  local -a queue=("organizations/$org")
  local node ptype pid sing flag sub
  while [[ ${#queue[@]} -gt 0 ]]; do
    node="${queue[0]}"; queue=("${queue[@]:1}")
    ptype="${node%%/*}"; pid="${node##*/}"
    sing="organization"; [[ "$ptype" == "folders" ]] && sing="folder"
    gc projects list --filter="parent.id=$pid AND parent.type=$sing" \
       --format="value(projectId)" 2>/dev/null
    if [[ "$ptype" == "organizations" ]]; then flag="--organization=$pid"; else flag="--folder=$pid"; fi
    while IFS= read -r sub; do
      [[ -z "$sub" ]] && continue
      [[ "$sub" != */* ]] && sub="folders/$sub"
      queue+=("$sub")
    done < <(gc resource-manager folders list $flag --format="value(name)" 2>/dev/null)
  done
}

discover_asset() {  # ORG -> projectIds (or numbers) via Cloud Asset Inventory
  gc asset search-all-resources --scope="organizations/$1" \
     --asset-types="cloudresourcemanager.googleapis.com/Project" --format=json 2>/dev/null \
  | jq -r '.[] | (.additionalAttributes.projectId // (.name | capture("projects/(?<n>[^/]+)").n) // empty)' 2>/dev/null
}

# ----- classification -------------------------------------------------------
classify_key() { # project uid name keytype targets has_app ai_csv gemini_enabled
  local project="$1" uid="$2" name="$3" keytype="$4" targets="$5" has_app="$6" ai_csv="$7" gemini_enabled="$8"
  local broad=0 ai_scoped=0 api
  [[ -z "${targets// }" ]] && broad=1
  contains "$targets" "cloudapis.googleapis.com" && broad=1
  for api in "${AI_LIST[@]}"; do contains "$targets" "$api" && ai_scoped=1; done

  if [[ "$keytype" == "authorization" ]]; then
    if [[ $broad -eq 1 ]]; then
      add_finding "$project" "CRITICAL" "key" "$uid" "$name" "$keytype" \
        "service-account-bound key is unrestricted -> can call AI APIs ($ai_csv) and bill your account"
    elif [[ $ai_scoped -eq 1 ]]; then
      add_finding "$project" "REVIEW" "key" "$uid" "$name" "$keytype" \
        "authorization key explicitly scoped to an AI API -> confirm intended; add IP/app restriction + App Check"
    elif [[ $VERBOSE -eq 1 ]]; then
      add_finding "$project" "OK" "key" "$uid" "$name" "$keytype" "authorization key, restricted to non-AI APIs"
    fi
  else
    if [[ "$gemini_enabled" == "1" && $broad -eq 1 ]]; then
      add_finding "$project" "MEDIUM" "key" "$uid" "$name" "$keytype" \
        "unrestricted standard key + Gemini enabled -> abusable until ${GEMINI_UNRESTRICTED_DEADLINE}, then rejected. Restrict now or move to an authorization key"
    elif [[ $broad -eq 1 ]]; then
      add_finding "$project" "MEDIUM" "key" "$uid" "$name" "$keytype" \
        "over-broad scope (no/Google-Cloud-APIs-bundle restriction); cannot reach Vertex (needs SA binding) but can call key-accepting APIs. Scope to only what it needs"
    elif [[ "$gemini_enabled" == "1" && $ai_scoped -eq 1 ]]; then
      add_finding "$project" "REVIEW" "key" "$uid" "$name" "$keytype" \
        "standard key scoped to Gemini -> migrate to an authorization key before ${GEMINI_STANDARD_DEADLINE}"
    elif [[ $VERBOSE -eq 1 ]]; then
      add_finding "$project" "OK" "key" "$uid" "$name" "$keytype" "standard key, restricted"
    fi
  fi
  if [[ "$has_app" == "0" && ( $broad -eq 1 || $VERBOSE -eq 1 ) ]]; then
    add_finding "$project" "LOW" "key" "$uid" "$name" "$keytype" \
      "no effective application restriction (referrer/IP/app allowlist is empty) -> usable from anywhere if leaked"
  fi
}

check_project() {
  local project="$1" enabled rc ai_on=() gemini_enabled=0 api ai_csv list_json kerr krc cnt i
  enabled=$(gc services list --enabled --project="$project" --format="value(config.name)" 2>/dev/null); rc=$?
  if [[ $rc -eq 124 ]]; then add_finding "$project" "ERROR" "project" "" "" "" "services list timed out after ${GCLOUD_TIMEOUT}s"; return; fi
  [[ -z "$enabled" ]] && { add_finding "$project" "SKIP" "project" "" "" "" "no access or no enabled services"; return; }

  for api in "${AI_LIST[@]}"; do grep -qx "$api" <<<"$enabled" && ai_on+=("$api"); done
  grep -qx "$GEMINI_API" <<<"$enabled" && gemini_enabled=1
  if [[ ${#ai_on[@]} -eq 0 ]]; then
    [[ $VERBOSE -eq 1 ]] && add_finding "$project" "OK" "project" "" "" "" "no dangerous AI APIs enabled"; return
  fi
  ai_csv=$(IFS=,; echo "${ai_on[*]}")
  progress "    AI enabled ($ai_csv) — inspecting keys..."

  kerr=$(mktemp)
  list_json=$(gc services api-keys list --project="$project" --format=json 2>"$kerr"); krc=$?
  if [[ $krc -eq 124 ]]; then
    add_finding "$project" "ERROR" "project" "" "" "" "key listing timed out after ${GCLOUD_TIMEOUT}s — NOT 'no keys'; raise --timeout"
    rm -f "$kerr"; return
  fi
  if [[ $krc -ne 0 ]]; then
    add_finding "$project" "ERROR" "project" "" "" "" "could not list keys (rc=$krc): $(head -1 "$kerr" | cut -c1-160)"
    rm -f "$kerr"; return
  fi
  rm -f "$kerr"
  [[ -z "$list_json" ]] && list_json="[]"

  cnt=$(jq 'length' <<<"$list_json" 2>/dev/null || echo 0)
  if [[ "$cnt" == "0" ]]; then
    add_finding "$project" "INFO" "project" "" "" "" "AI APIs enabled ($ai_csv); list returned zero keys"; return
  fi

  for (( i=0; i<cnt; i++ )); do
    local uid name sa keytype targets has_app appcount
    uid=$(jq -r ".[$i].uid // empty" <<<"$list_json")
    name=$(jq -r ".[$i].displayName // \"unnamed\"" <<<"$list_json")
    sa=$(jq -r ".[$i].serviceAccountEmail // empty" <<<"$list_json")
    [[ -n "$sa" ]] && keytype="authorization" || keytype="standard"
    targets=$(jq -r ".[$i].restrictions.apiTargets[].service // empty" <<<"$list_json" 2>/dev/null | tr '\n' ' ')
    appcount=$(jq -r "
      ([.[$i].restrictions.browserKeyRestrictions.allowedReferrers // []]
       + [.[$i].restrictions.serverKeyRestrictions.allowedIps // []]
       + [.[$i].restrictions.androidKeyRestrictions.allowedApplications // []]
       + [.[$i].restrictions.iosKeyRestrictions.allowedBundleIds // []])
      | map(length) | add" <<<"$list_json" 2>/dev/null || echo 0)
    [[ "${appcount:-0}" -gt 0 ]] && has_app=1 || has_app=0
    classify_key "$project" "$uid" "$name" "$keytype" "$targets" "$has_app" "$ai_csv" "$gemini_enabled"
  done
  progress "    inspected $cnt key(s)"
}

render_text() {
  local last="" rec project sev cat uid name keytype detail color tag
  if [[ ${#FINDINGS[@]} -eq 0 ]]; then echo "No findings. (Re-run with --verbose to see clean projects.)"; return; fi
  for rec in "${FINDINGS[@]}"; do
    IFS="$US" read -r project sev cat uid name keytype detail <<<"$rec"
    [[ "$project" != "$last" ]] && { echo; echo "${BLU}=== ${project} ===${RST}"; last="$project"; }
    case "$sev" in
      CRITICAL) color="$RED"; tag="[CRITICAL]" ;;
      MEDIUM)   color="$YEL"; tag="[MEDIUM]  " ;;
      LOW)      color="$DIM"; tag="[low]     " ;;
      REVIEW)   color="$YEL"; tag="[review]  " ;;
      INFO)     color="$BLU"; tag="[info]    " ;;
      ERROR)    color="$RED"; tag="[ERROR]   " ;;
      SKIP)     color="$DIM"; tag="[skipped] " ;;
      *)        color="$GRN"; tag="[ok]      " ;;
    esac
    if [[ "$cat" == "key" ]]; then
      printf "  %s%s%s %s (%s) [%s] — %s\n" "$color" "$tag" "$RST" "$name" "$uid" "$keytype" "$detail"
    else
      printf "  %s%s%s %s\n" "$color" "$tag" "$RST" "$detail"
    fi
  done
  echo; echo "Summary: ${RED}${CRITICAL_COUNT} CRITICAL${RST}, ${YEL}${MEDIUM_COUNT} MEDIUM${RST}."
}
render_csv() {
  echo "project,severity,category,key_uid,key_name,key_type,detail"
  local rec project sev cat uid name keytype detail
  for rec in "${FINDINGS[@]}"; do
    IFS="$US" read -r project sev cat uid name keytype detail <<<"$rec"
    printf "%s,%s,%s,%s,%s,%s,%s\n" "$(csv_escape "$project")" "$(csv_escape "$sev")" "$(csv_escape "$cat")" \
      "$(csv_escape "$uid")" "$(csv_escape "$name")" "$(csv_escape "$keytype")" "$(csv_escape "$detail")"
  done
}
render_json() {
  local rec project sev cat uid name keytype detail first=1
  printf '['
  for rec in "${FINDINGS[@]}"; do
    IFS="$US" read -r project sev cat uid name keytype detail <<<"$rec"
    [[ $first -eq 0 ]] && printf ','; first=0
    printf '{"project":"%s","severity":"%s","category":"%s","key_uid":"%s","key_name":"%s","key_type":"%s","detail":"%s"}' \
      "$(json_escape "$project")" "$(json_escape "$sev")" "$(json_escape "$cat")" \
      "$(json_escape "$uid")" "$(json_escape "$name")" "$(json_escape "$keytype")" "$(json_escape "$detail")"
  done
  printf ']\n'
}
render() { case "$FORMAT" in text) render_text;; csv) render_csv;; json) render_json | jq .;; esac; }

# ===== library guard: when sourced for testing, stop here ===================
if [[ -n "${GCAUDIT_LIB_ONLY:-}" ]]; then return 0 2>/dev/null || exit 0; fi

# ===== main =================================================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org) ORG_ID="${2:-}"; shift 2 ;;
    --project) PROJECTS+=("${2:-}"); shift 2 ;;
    --projects-file) PROJECTS_FILE="${2:-}"; shift 2 ;;
    --discovery) DISCOVERY="${2:-}"; shift 2 ;;
    --apis) DANGEROUS_APIS="${2:-}"; shift 2 ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --timeout) GCLOUD_TIMEOUT="${2:-60}"; shift 2 ;;
    --fail-on-critical) FAIL_ON_CRITICAL=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    --quiet-progress) QUIET_PROGRESS=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --version) echo "$PROG v$VERSION"; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

case "$FORMAT" in text|csv|json) ;; *) die "invalid --format: $FORMAT" ;; esac
case "$DISCOVERY" in recursive|asset|flat) ;; *) die "invalid --discovery: $DISCOVERY (recursive|asset|flat)" ;; esac
IFS=',' read -r -a AI_LIST <<<"$DANGEROUS_APIS"

if [[ "$FORMAT" == "text" && $NO_COLOR -eq 0 && -t 1 && -z "$OUTPUT" ]]; then
  RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; DIM=$'\033[2m'; RST=$'\033[0m'
else RED=""; YEL=""; GRN=""; BLU=""; DIM=""; RST=""; fi

command -v gcloud >/dev/null 2>&1 || die "gcloud not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found — install it (e.g. sudo apt-get install -y jq)"
command -v timeout >/dev/null 2>&1 && GCAUDIT_HAVE_TIMEOUT=1 || progress "note: 'timeout' not found; per-call timeouts disabled"
ACTIVE=$(gc auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
[[ -n "$ACTIVE" ]] || die "no active gcloud credentials (run: gcloud auth login)"

if [[ -n "$ORG_ID" ]]; then
  progress "discovering projects (mode: $DISCOVERY) under org $ORG_ID..."
  case "$DISCOVERY" in
    flat)      mapfile -t PROJECTS < <(discover_flat "$ORG_ID" | sort -u) ;;
    recursive) mapfile -t PROJECTS < <(discover_recursive "$ORG_ID" | sort -u) ;;
    asset)     mapfile -t PROJECTS < <(discover_asset "$ORG_ID" | sort -u) ;;
  esac
  if [[ ${#PROJECTS[@]} -eq 0 ]]; then
    case "$DISCOVERY" in
      asset) die "no projects via Cloud Asset — ensure cloudasset.googleapis.com is enabled and you hold roles/cloudasset.viewer on the org, or try --discovery recursive" ;;
      recursive) die "no projects under org $ORG_ID — recursive crawl needs resourcemanager.projects.list and .folders.list; check perms" ;;
      flat) die "no direct-child projects under org $ORG_ID (folder-nested ones need --discovery recursive)" ;;
    esac
  fi
  progress "discovered ${#PROJECTS[@]} project(s)"
elif [[ -n "$PROJECTS_FILE" ]]; then
  [[ -r "$PROJECTS_FILE" ]] || die "cannot read projects file: $PROJECTS_FILE"
  mapfile -t PROJECTS < <(grep -vE '^\s*(#|$)' "$PROJECTS_FILE")
elif [[ ${#PROJECTS[@]} -eq 0 ]]; then
  cur=$(gc config get-value project 2>/dev/null)
  [[ -n "$cur" && "$cur" != "(unset)" ]] || die "no scope given and no active project"
  PROJECTS=("$cur")
fi

if [[ -n "$ORG_ID" ]]; then
  progress "checking org policy (SA-key binding)..."
  enf=$(gc org-policies describe iam.managed.disableServiceAccountApiKeyCreation \
        --organization="$ORG_ID" --format="value(spec.rules[0].enforce)" 2>/dev/null)
  if [[ "$enf" == "True" || "$enf" == "true" ]]; then
    add_finding "(org $ORG_ID)" "INFO" "policy" "" "" "" "SA-key binding is BLOCKED org-wide -> no authorization keys can exist; no key can reach Vertex"
  elif [[ -n "$enf" ]]; then
    add_finding "(org $ORG_ID)" "INFO" "policy" "" "" "" "SA-key binding is ALLOWED org-wide -> authorization keys are possible; treat any AI-scoped one as high value"
  fi
fi

PROJ_TOTAL=${#PROJECTS[@]}; idx=0
for p in "${PROJECTS[@]}"; do
  [[ -z "$p" ]] && continue
  idx=$((idx+1)); progress "[$idx/$PROJ_TOTAL] scanning $p..."
  check_project "$p"
done
progress "scan complete; rendering report"

if [[ -n "$OUTPUT" ]]; then render >"$OUTPUT"; echo "$PROG: wrote ${#FINDINGS[@]} finding(s) to $OUTPUT" >&2; else render; fi
[[ $FAIL_ON_CRITICAL -eq 1 && $CRITICAL_COUNT -gt 0 ]] && exit 2
exit 0

