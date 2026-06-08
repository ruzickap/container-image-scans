# AGENTS.md

Guidance for AI agents working on **container-image-scans**.

## What this repo is

Nightly job that scans container images (listed in `images.yml`) with
**trivy** and **grype**, then stores SARIF + extracted CVEs in
**Supabase** (PostgreSQL). A Next.js dashboard on GitHub Pages is
**planned but not yet implemented** (see gotcha below).

Real, present components: `scripts/` (bash scanners), `supabase/`
(schema + migrations), `.github/workflows/` (CI + automation).

## Critical gotchas

- **`web/` does not exist yet.** The README, mise `web:*`/`build`
  tasks, `deploy-web.yml`, and `web/.env.example` reference a Next.js
  app that has never been committed. Do not assume it is there; the
  `web:install`/`web:dev`/`web:build`/`build` mise tasks will fail
  until `web/` is created. Treat any web-app instructions as the
  intended design for new code, not existing code.
- **`.pre-commit-config.yaml` is gitignored** (see `.gitignore`) and
  symlinked locally. It is not in the repo; do not edit or rely on it
  being present in CI.
- **Lint runs only on non-main branches.** `mega-linter.yml` triggers
  on `branches-ignore: [main]`, so push work to a branch to get
  linting. It also extracts every `bash`/`shell`/`sh` code block from
  changed `*.md` files and shell-checks them — keep markdown shell
  snippets syntactically valid.

## Tooling and commands

`mise` is the task runner and tool manager. Run `mise install` once to
get node 24, supabase CLI, trivy, grype, yq, and fnox at pinned
versions (`mise.toml`).

| Command              | What it does                                       |
| -------------------- | -------------------------------------------------- |
| `mise run scan`      | Scan all images, print CVE summary (no Supabase)   |
| `mise run scan:upload` | Scan + upload to Supabase (needs env, see below) |
| `mise run db:push`   | Link Supabase project + push migrations            |

`scan`/`scan:upload` wrap `scripts/scan-and-upload.sh`; `db:push` wraps
`scripts/apply-schema.sh`. Scanning requires **Docker** running locally.

Required env for uploads/migrations (auto-loaded from AWS Parameter
Store via the `fnox-env` mise plugin when an AWS profile `my-aws` in
`eu-central-1` is available, see `fnox.toml`):

- `scan:upload`: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`
- `db:push`: `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_REF`,
  `SUPABASE_DB_PASSWORD`

### Verifying changes (no test suite)

- Shell: `shellcheck scripts/*.sh` and
  `shfmt --case-indent --indent 2 --space-redirects --diff scripts/`
  (CI excludes `SC2317`).
- Workflows: `actionlint` after editing any file in
  `.github/workflows/`.
- Markdown: `rumdl <file>` (config `.rumdl.toml`) and `lychee .`
  (config `lychee.toml`) for links.

## Supabase data access (important)

- **Writes use PostgREST + curl with the `service_role` key**, not the
  supabase CLI. The CLI only links/pushes migrations; it cannot
  insert or select rows. See `upload_scan`/`upload_cves` in
  `scripts/scan-and-upload.sh`.
- The web app (when built) reads with the **anon** key; anon is
  SELECT-only and safe to ship in the static site (enforced by RLS).
- CVEs are uploaded in **batches of 100** to avoid payload limits.
- Tables: `image_groups`, `container_images`, `scans`, `cves`
  (`scans` cascades to `cves`). Schema, RLS, grants, seed data, and a
  `pg_cron` 1-year retention job live in
  `supabase/migrations/20250301000000_initial_schema.sql`.

### Adding or changing images

`images.yml` is the source of truth, but it is **not auto-synced**.
Changing it requires matching edits to `supabase/migrations/`,
`supabase/schema.sql`, and the image table in `README.md` (the header
comment in `images.yml` says the same). Migrations are append-only;
add a new timestamped file rather than editing applied ones.

## Conventions specific to this repo

- **Bash** (`scripts/`): `#!/usr/bin/env bash`, `set -euo pipefail`,
  UPPERCASE vars (including `local`), always quote `"${VAR}"`,
  `function_name() {}` form, `die()` for fatal errors, `|| true` for
  non-fatal commands, `# ── section ──` banner comments.
- **SQL** (`supabase/`): start files with `/* tsqllint-disable */`,
  UPPERCASE keywords, snake_case identifiers, `bigint GENERATED ALWAYS
  AS IDENTITY PRIMARY KEY`, RLS on every table (public `SELECT`,
  service-role `INSERT`), `ON CONFLICT ... DO NOTHING` for idempotent
  seeds.
- **Workflows**: runner `ubuntu-24.04-arm`; install tools via
  `jdx/mise-action` (not Homebrew or `setup-node`); pin actions to
  full SHA with a `# vX.Y.Z` comment; `permissions: read-all` unless a
  job needs more.
- **General**: 2-space indent everywhere; wrap markdown at 80 cols
  (code blocks exempt); trailing newline; no trailing whitespace.

## Git / PR

- Conventional commits `<type>: <description>`, imperative, lowercase,
  no period, subject and body lines ≤ 72 chars (validated by
  `commit-check`).
- Branches: `<type>/<description>` per Conventional Branch
  (`feature/`, `fix/`, `chore/`, ...).
- Open PRs as **draft**; title must be a valid conventional-commit
  (validated by `semantic-pull-request`).
- Renovate and Release Please are automated; do not hand-edit
  `CHANGELOG.md` (it is excluded from all linters).
