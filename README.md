# gcp-ai-key-audit

Find the GCP API keys that can quietly run generative AI **on your bill** — before an attacker (or the next billing cycle) finds them for you.

`gcp-ai-key-audit` scans one or many Google Cloud projects for API keys whose restrictions make them dangerous when an AI API (Vertex / Agent Platform or the Gemini API) is enabled, and grades each finding by what it can *actually* reach.

> **Read-only.** This tool never creates, modifies, deletes, or rotates anything. It only calls `list`/`describe`/`search`, and the secret key strings are never fetched. You can run it against production with confidence.

---

## Why this exists

Google uses one API-key format for two very different jobs — public project identifiers (Maps, Firebase) and sensitive credentials. For years those client keys were generated **unrestricted by default**, and keys created via gcloud/Terraform/CI skip the Console's mandatory-restriction prompt entirely. When an AI API gets enabled on the same project, every unrestricted key can silently gain access to it — and generative image/video calls run up cost faster than billing alerts fire.

There's also a clock on it. Google is retiring standard-key access to the Gemini API:

- **2026-06-19** — the Gemini API begins rejecting **unrestricted standard keys**.
- **2026-09** — the Gemini API rejects **all standard keys**; you must migrate to authorization keys.

This tool finds the keys those deadlines (and that billing risk) apply to.

---

## What it checks — the risk model

A crucial distinction most scanners miss: **only an *authorization key* (one bound to a service account) can call Vertex / Agent Platform.** A plain *standard* key cannot reach it no matter how broad its restrictions. The Gemini API still accepts standard keys, but only until the deadlines above. Findings are graded accordingly:

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | Authorization key (service-account-bound), unrestricted or AI-scoped, in a project with an AI API enabled → can bill AI to your account |
| **MEDIUM** | Standard key + Gemini enabled + unrestricted (time-bound risk), **or** standard key with over-broad scope (no/`cloudapis` bundle restriction) |
| **REVIEW** | Key explicitly scoped to an AI API — confirm it's intended |
| **LOW** | Any broad key with no *effective* application restriction (empty referrer/IP/app allowlist) → usable from anywhere if leaked |
| **INFO / SKIP / ERROR** | Org-policy context, projects with no access/no services, or calls that failed (so a failure is never mistaken for "clean") |

Empty restriction objects (e.g. `browserKeyRestrictions: {}`) are correctly treated as **no** restriction, not as "restricted."

---

## Requirements

- **gcloud**, authenticated (`gcloud auth login`)
- **jq**
- *Optional:* coreutils **`timeout`** (enables per-call timeouts; the tool degrades gracefully without it)

```bash
# Debian/Ubuntu
sudo apt-get install -y jq
# macOS
brew install jq
```

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/empryze/gcp-ai-key-audit/main/gcp-ai-key-audit.sh
# (optional) verify the checksum you publish alongside it:
#   sha256sum -c gcp-ai-key-audit.sh.sha256
chmod +x gcp-ai-key-audit.sh
```

---

## Quick start

```bash
# Audit an entire org (walks folders to any depth by default)
./gcp-ai-key-audit.sh --org 123456789012

# A single project, or several
./gcp-ai-key-audit.sh --project my-prod
./gcp-ai-key-audit.sh --project my-prod --project my-prod-eu

# Export a report
./gcp-ai-key-audit.sh --org 123456789012 --format csv --output audit.csv

# CI gate: non-zero exit if anything CRITICAL is found
./gcp-ai-key-audit.sh --org 123456789012 --fail-on-critical
```

### Sample output

```
=== my-prod ===
  [MEDIUM]   Browser key (auto created by Firebase) (xxxxxxxx-....) [standard] — over-broad scope
             (no/Google-Cloud-APIs-bundle restriction); cannot reach Vertex (needs SA binding) but
             can call key-accepting APIs. Scope to only what it needs
  [low]      Browser key (auto created by Firebase) (xxxxxxxx-....) [standard] — no effective
             application restriction (referrer/IP/app allowlist is empty) -> usable from anywhere if leaked

Summary: 0 CRITICAL, 4 MEDIUM.
```

---

## Usage

```
USAGE: gcp-ai-key-audit.sh [scope] [options]

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
  --apis LIST                  Comma-separated dangerous APIs
                               (default: generativelanguage.googleapis.com,aiplatform.googleapis.com)
  --format text|csv|json       Output format (default: text)
  --output FILE                Write to FILE instead of stdout
  --timeout SECONDS            Max seconds per gcloud call (default: 60; 0 = none)
  --fail-on-critical           Exit 2 if any CRITICAL finding (CI gating)
  --verbose                    Also report clean projects/keys
  --quiet-progress             Suppress per-project progress on stderr
  --no-color                   Disable colored output
  -h, --help / --version
```

### Discovery modes

Picking the wrong scope is how real keys hide. In organizations that use folders, a flat org query only returns projects directly under the org node and **silently misses everything nested in folders**.

- **`recursive`** (default) — breadth-first walk of the folder tree to any depth. Real-time, needs only `resourcemanager.projects.list` + `resourcemanager.folders.list`.
- **`asset`** — a single Cloud Asset Inventory query. Fast and flat regardless of nesting, but needs the Cloud Asset API enabled and `roles/cloudasset.viewer`, and is eventually consistent (can lag a few minutes).
- **`flat`** — direct org children only. Fast, but misses folder-nested projects. Kept for parity/debugging.

`recursive` and `asset` should agree on the project list; running both is a good cross-check.

---

## Required IAM

Run as an identity with, at the scope you're auditing:

- `resourcemanager.projects.list` (and `resourcemanager.folders.list` for `--discovery recursive`)
- `serviceusage.services.list` — to read enabled APIs per project
- `serviceusage.apiKeys.list` (e.g. **`roles/serviceusage.apiKeysViewer`**) — to list keys
- *For `--discovery asset`:* **`roles/cloudasset.viewer`** + the Cloud Asset API enabled
- *Optional:* `orgpolicy.policy.get` — lets the tool report whether SA-key binding is blocked org-wide

The simplest setup is org-level `roles/viewer` plus `roles/serviceusage.apiKeysViewer`. **Running with org-wide read is strongly recommended** — see Limitations.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Completed (no CRITICAL, or `--fail-on-critical` not set) |
| `2`  | CRITICAL findings present **and** `--fail-on-critical` set |
| `3`  | Usage or dependency error |

---

## Limitations — what a clean run does *not* prove

This is a security tool, so its blind spots are stated plainly. A clean result means *"no risky keys in the projects this identity could read,"* which is **not** the same as *"no risky keys exist."*

- **Skipped ≠ cleared.** If your identity can't read a project's enabled services, that project is skipped and never inspected for keys. Run with org-wide read so a `SKIP` means "empty," not "blind." (Google's Apps Script `sys-` projects, for example, are returned to inventory but are not readable unless you're their owner.)
- **Scope is what you pass.** `--org` only covers that organization. Projects in another org, or with no organization at all, won't be discovered — even though a console "unrestricted key" banner is account-wide.
- **Point-in-time.** It's a snapshot; keys and API enablement can change afterward. `--discovery asset` additionally reads eventually-consistent data.
- **API vs application restrictions.** It flags empty application allowlists, but does not validate the *values* of populated ones.
- **AI-enabled projects only.** Keys are inspected for AI risk only where an AI API is enabled; a latent unrestricted key in a non-AI project isn't flagged as AI risk (though it's still worth restricting).

To pin down a specific exposure (e.g. a console banner), the fastest source of truth is the banner's own link, and the broadest is a Cloud Asset query across the org for the enabled service.

---

## Remediating a flagged key

- **Scope it.** Restrict each key to only the APIs it needs (`gcloud services api-keys update KEY_ID --api-target=service=...`; note this replaces the full set).
- **Lock it to a surface.** Add an application restriction — referrer (browser), bundle ID (iOS), package+SHA (Android), or IP range (server).
- **Never share one key** across Maps/Firebase and an AI API.
- **Prefer no key at all** for server-to-server: use Application Default Credentials / Workload Identity Federation with IAM.
- **For client-side AI**, use Firebase App Check rather than relying on key restrictions alone.

Validate changes in a staging/preprod project before production.

---

## License

MIT. See [LICENSE](LICENSE).

```
Copyright (c) 2026 <DUKE LEE / EMPRYZE>
```

## Disclaimer

Provided "as is", without warranty of any kind. This tool reports configuration risk; it is not a guarantee of security and is not a substitute for a full security review. You are responsible for any changes you make to your environment based on its output.
