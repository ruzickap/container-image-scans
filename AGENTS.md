# AGENTS.md

Guidance for AI agents working on **container-image-scans**.

## What this repo is

Nightly job that scans container images (listed in `images.yml`) with
**trivy** and **grype**, then stores the extracted CVEs in **Amazon
DynamoDB**. A dashboard (`web/`, Vite + Svelte, GitHub Pages) reads them
directly from the browser with **Cognito guest credentials** - there is
no backend.

Components: `scripts/scan_and_upload.py` (scanner + uploader, Python), `web/`
(dashboard), `.github/workflows/` (CI + automation).

## Critical gotchas

- **The AWS resources are not managed here.** The DynamoDB table
  `container-image-scans`, the Cognito identity pool, the IAM roles, and
  the alarms live in OpenTofu in `ruzickap/my-git-projects`
  (`opentofu/aws`, account `my-aws`, `eu-central-1`). Change them there.
- **Free tier limits shape the code.** The table has only **2 RCU /
  25 WCU**: writes are throttled (the script retries `UnprocessedItems`),
  and readers must use `Query` / `GetItem` on small partitions. The guest
  role can not `Scan` or write. Do not add global secondary indexes.
- **Items are max. 400 KB** - do not store the full scanner reports.
- **Scanner results come from their JSON reports** (`trivy --format json`,
  `grype --by-cve -o json`), mapped by `trivy_cves()` / `grype_cves()` -
  do not parse the free-text messages.
- **Everything in the table is public** (the identity pool ID is in
  `web/src/lib/dynamodb.ts`). Store only public scan data.
- **JavaScript / TypeScript style is Prettier, not standard.**
  `.mega-linter.yml` sets `JAVASCRIPT_DEFAULT_STYLE` /
  `TYPESCRIPT_DEFAULT_STYLE: prettier` and is kept by multi-gitter
  (`checkout_files` in `ruzickap/my-git-projects`) - do not reset it to
  the shared default.
- **`.pre-commit-config.yaml` is gitignored** (see `.gitignore`) and
  symlinked locally. It is not in the repo; do not edit or rely on it
  being present in CI.
- **Lint runs only on non-main branches.** `mega-linter.yml` triggers
  on `branches-ignore: [main]`, so push work to a branch to get
  linting. It also extracts every `bash`/`shell`/`sh` code block from
  changed `*.md` files and shell-checks them - keep markdown shell
  snippets syntactically valid.

## Tooling and commands

`mise` is the task runner and tool manager. Run `mise install` once to
get Bun, grype, trivy, and uv at pinned versions (uv installs Python from
`.python-version` and the scanner dependencies from `uv.lock`)
(`mise.toml`).

| Command                | What it does                                      |
|------------------------|---------------------------------------------------|
| `mise run scan`        | Scan all images, print CVE summary (no AWS)       |
| `mise run scan:upload` | Scan + upload to DynamoDB (needs AWS credentials) |
| `mise run web:dev`     | Dashboard dev server with hot reload              |
| `mise run web:test`    | Dashboard tests (Vitest, no AWS access)           |
| `mise run web:build`   | Type-check + build the dashboard to `web/dist/`   |

Scanning requires **Docker**. Uploads need AWS credentials allowed to
write to the table: GitHub Actions assume the
`CONTAINER_IMAGE_SCANS_AWS_ROLE_TO_ASSUME` role via OIDC, locally use e.g.
`AWS_PROFILE=my-aws`. No secrets are stored in this repo.

### Verifying changes

- Scanner: `mise run scan:test` (pytest - fake scanner reports and a fake
  DynamoDB table, no Docker / AWS). Lint like MegaLinter (without the
  project dependencies): `uvx ruff check`, `uvx ruff format --check`,
  `uvx isort --check-only`, `uvx flake8`, `uvx pylint`, `uvx mypy`,
  `uvx pyright`, `uvx bandit -c pyproject.toml` on `scripts/` and `tests/`
  (`[tool.bandit]` skips B101 - pytest tests use `assert`).
  CI runs the tests on every branch push touching the scanner
  (`scanner-tests.yml`, not a required check).
- Uploads without touching AWS: run
  [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html),
  create the table (e.g. with the AWS CLI), and set
  `AWS_ENDPOINT_URL_DYNAMODB=http://localhost:8000` (plus dummy
  `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`). `IMAGES_FILE` points
  the script to a shorter image list.
- Dashboard: `mise run web:test` (Vitest), `mise run web:build`
  (svelte-check + tsc + build), and `npx prettier --check` for
  formatting. CI runs the same on every branch push touching `web/`
  (`web-tests.yml`, not a required check - do not merge a red run);
  `deploy-web.yml` on `main` only type-checks, builds and deploys.
  Against DynamoDB Local build or run it with
  `VITE_DYNAMODB_ENDPOINT=http://localhost:8000` and test in a browser
  without web security (DynamoDB Local's CORS answers do not satisfy the
  AWS SDK).
- Workflows: `actionlint` after editing any file in
  `.github/workflows/`.
- Markdown: `rumdl <file>` (config `.rumdl.toml`) and `lychee .`
  (config `lychee.toml`) for links.

## Data model

See [README.md](README.md#data-model). In short:

- `pk = LATEST`, `sk = <group>#<vendor>#<scanner>` - one summary item per
  image and scanner, overwritten by every scan; `cves_pk` points to its CVEs
- `pk = HISTORY#<group>`, `sk = <scanned_at>#<vendor>#<scanner>` - the
  summary of every scan (dashboard charts, raw data per day)
- `pk = CVES#<group>#<vendor>#<scanner>#<scanned_at>`,
  `sk = <CVE ID>#<package>` - the CVEs of one scan, written **before**
  the `HISTORY` and `LATEST` items
- `pk = LIFECYCLE#<group>#<vendor>#<scanner>`, `sk = <CVE ID>#<package>` -
  `first_seen` / `fix_seen` / `removed_at` of every CVE of an image,
  only changes are written (`lifecycle_items()`); a CVE found again
  keeps the finished lifecycle as `sk = <CVE ID>#<package>#<removed_at>`
- `pk = DAYS`, `sk = <YYYY-MM-DD>` - the days with an upload run
- Every item has `expires_at` (TTL, two years)

### Adding or changing images

Edit `images.yml` (source of truth, read by the scan script) and the
image table in `README.md`. Structure: `<group>: {description, images:
{<vendor>: {image, description}}}`. Use only rolling tags (`latest`,
`alpine`, `slim`, ...) and no version numbers in the descriptions. No
database change is needed. A changed image of the same group / vendor
replaces its dashboard row; removed groups / vendors keep their `LATEST`
items until the TTL deletes them.

## Conventions specific to this repo

- **Python** (`scripts/`, `tests/`): Python from `.python-version`,
  dependencies in `pyproject.toml` + `uv.lock` (add them with `uv add`),
  run with `uv run --locked`. Type hints and docstrings everywhere, 79
  character lines (flake8 / ruff / isort agree on it), `subprocess` only
  with fixed argument lists (no shell, `# nosec B603`). Pure functions for
  the data mapping, tested in `tests/` - add a test for every new
  behavior.
- **Web** (`web/`): Vite + Svelte 5 (runes) + TypeScript, scaffolded from
  the official `create-vite` `svelte-ts` template. Data access and types
  live in `src/lib/dynamodb.ts`. Render scanner data with Svelte `{...}`
  expressions (escaped), never `{@html}`; link only `https://` URLs.
  Prettier style (double quotes, semicolons). Package manager and runtime:
  **Bun** (`bun.lock`, `web/bunfig.toml` runs scripts on Bun - keep it,
  without it the scripts quietly run on Node.js). Vitest needs
  `pool: "threads"` on Bun (the default process pool fails). Tests next
  to the code (`*.test.ts`, Vitest + Svelte Testing Library + jsdom) with
  the AWS SDK / `query` mocked - add a test for every new behavior.
- **Workflows**: runner `ubuntu-26.04-arm`; install tools via
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
