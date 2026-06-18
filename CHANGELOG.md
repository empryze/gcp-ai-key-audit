# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-06-13
### Added
- Pluggable project discovery for organizations with folders, via `--discovery`:
  - `recursive` (default): breadth-first walk of the folder tree to any depth.
  - `asset`: single Cloud Asset Inventory query (needs the Cloud Asset API + `roles/cloudasset.viewer`).
  - `flat`: direct org children only (fast; misses folder-nested projects).
- Library guard so functions can be sourced and unit-tested without running the tool.
### Changed
- `--discovery recursive` is now the default for `--org` (the previous flat behavior
  silently missed folder-nested projects).

## [1.1.3] - 2026-06-13
### Changed
- Enumerate and analyze keys from a single `api-keys list --format=json` call,
  parsed with jq; removed the per-key `describe` loop.
- Empty restriction objects (e.g. `browserKeyRestrictions: {}`) are now correctly
  treated as **no** application restriction.
### Added
- `jq` is now a required dependency.

## [1.1.2] - 2026-06-09
### Fixed
- A failed or timed-out key-list call is no longer mislabeled as "no keys present";
  it is now reported as an `ERROR` finding with the underlying reason.

## [1.1.1] - 2026-06-09
### Added
- Per-call timeout guard, non-interactive gcloud invocation (no stdin hangs),
  and live per-project progress on stderr.

## [1.1.0] - 2026-06-09
### Added
- Distinction between authorization (service-account-bound) and standard keys;
  only authorization keys can reach Vertex / Agent Platform.
- Best-effort org-policy context (SA-key binding blocked vs allowed).
- `key_type` column in CSV/JSON output.
### Changed
- Severity model reworked around the authorization-vs-standard distinction.

## [1.0.0] - 2026-06-09
### Added
- Initial release: scan a project, list of projects, or organization for API keys
  that are dangerous when an AI API is enabled.
- CRITICAL/MEDIUM/LOW/REVIEW findings; text, CSV, and JSON output.
- `--fail-on-critical` for CI gating.

[1.2.0]: https://github.com/empryze/gcp-ai-key-audit/releases/tag/v1.2.0
[1.1.3]: https://github.com/empryze/gcp-ai-key-audit/releases/tag/v1.1.3
[1.1.2]: https://github.com/empryze/gcp-ai-key-audit/releases/tag/v1.1.2
[1.1.1]: https://github.com/empryze/gcp-ai-key-audit/releases/tag/v1.1.1
[1.1.0]: https://github.com/empryze/gcp-ai-key-audit/releases/tag/v1.1.0
[1.0.0]: https://github.com/empryze/gcp-ai-key-audit/releases/tag/v1.0.0
