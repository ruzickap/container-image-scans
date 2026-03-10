# AI Agent Guidelines

Instructions for AI coding agents working on **container-image-scans**.

## Build / Lint / Test Commands

### Prerequisites

Run `mise install` once after cloning to install Node.js, Supabase
CLI, yq, and all lint tools defined in `.mise.toml`.

### Next.js web app (`web/`)

```bash
npm ci        # install dependencies (run from web/)
npm run dev   # development server
npm run build # production build (static export to web/out/)
npm run lint  # ESLint via next lint
```

There is no test suite yet. Verify changes by running `npm run build`
in `web/` — the static export must succeed without errors.

### Shell scripts (`scripts/`)

```bash
# Lint (exclude SC2317 — unreachable command warning)
shellcheck scripts/scan-and-upload.sh

# Check formatting (2-space indent, space redirects)
shfmt --case-indent --indent 2 --space-redirects \
  --diff scripts/scan-and-upload.sh

# Apply formatting in place
shfmt --case-indent --indent 2 --space-redirects \
  --write scripts/scan-and-upload.sh
```

### GitHub Actions workflows

```bash
actionlint                # validate all workflow files
```

### Markdown and links

```bash
rumdl README.md AGENTS.md # lint markdown (config in .rumdl.toml)
lychee .                  # check links (config in lychee.toml)
```

### Pre-commit hooks

```bash
pre-commit install && pre-commit install --hook-type commit-msg
pre-commit run --all-files # run all hooks manually
```

Hooks include: shellcheck, shfmt, prettier (excludes `*.md`),
yamllint, actionlint, rumdl, codespell, gitleaks, keep-sorted,
commitizen, and commit-check.

## Project Structure

| Path                  | Purpose                               |
|-----------------------|---------------------------------------|
| `web/`                | Next.js 15 dashboard (static export)  |
| `web/src/lib/`        | Supabase client, types, data fetchers |
| `web/src/components/` | React components (client-side)        |
| `web/src/app/`        | Next.js app router pages and layout   |
| `scripts/`            | Bash scripts for CI                   |
| `supabase/`           | Database schema and seed data         |
| `.github/workflows/`  | GitHub Actions workflow files         |

## Code Style

### General

- **Indentation**: 2 spaces everywhere (TS, CSS, YAML, SQL, bash).
- **Line width**: Wrap lines at 80 characters for markdown files.
- **Trailing newline**: All files end with a single newline.
- **No trailing whitespace**.

### TypeScript / React (`web/src/`)

- **Formatter**: Prettier with default settings and
  `--html-whitespace-sensitivity=ignore`.
- **Strict mode**: `tsconfig.json` has `strict: true`.
- **Imports**: Use `@/` path alias for internal imports
  (e.g. `@/lib/supabase`, `@/components/HistoryCharts`).
  - External packages first, then internal imports, separated by
    a blank line.
  - Use `import type { ... }` when importing only types.
- **Client components**: Start with `"use client";` on line 1.
- **Component exports**: Named exports (`export function Foo`).
  Exception: `page.tsx` and `layout.tsx` use `export default`.
- **Interface naming**: `Props` for component prop interfaces.
  PascalCase for domain types (`ImageGroup`, `ContainerImage`,
  `Scan`, `Cve`).
- **State management**: React hooks only (`useState`, `useMemo`,
  `useCallback`, `useEffect`). No external state libraries.
- **Data fetching**: All Supabase queries go through functions in
  `web/src/lib/supabase.ts`. Components never use `supabase`
  directly.
- **Error handling**: Wrap async calls in try/catch, log with
  `console.error("Failed to <action>:", err)`, set loading state
  in a `finally` block.
- **Nullish coalescing**: Prefer `??` over `||`. Use `data ?? []`
  after Supabase queries.
- **CSS**: Use CSS custom properties from `globals.css`
  (`var(--bg)`, `var(--text-muted)`, `var(--critical)`, etc.).
  Prefer CSS classes over inline styles.

### Bash (`scripts/`)

- **Shebang**: `#!/usr/bin/env bash`
- **Strict mode**: Always `set -euo pipefail`
- **Variables**: All UPPERCASE (`SARIF_FILE`, `SCAN_ID`). Local
  variables also UPPERCASE, declared with `local`.
- **Quoting**: Always double-quote expansions (`"${VAR}"`).
- **Formatting**: `shfmt --case-indent --indent 2
  --space-redirects`.
- **Continuation lines**: 2-space indent from command start, not
  aligned to opening parens.
- **Functions**: `function_name() { ... }` form (no `function`
  keyword). Place helpers before main logic.
- **Error handling**: `die()` helper for fatal errors. `|| true`
  for non-fatal commands.
- **Section comments**: `# ── section name ──...` banner style.

### SQL (`supabase/`)

- **Keywords**: UPPERCASE (`CREATE TABLE`, `NOT NULL`, `DEFAULT`).
- **Identifiers**: lowercase snake_case (`image_groups`,
  `cve_count`).
- **Primary keys**: `bigint GENERATED ALWAYS AS IDENTITY
  PRIMARY KEY`.
- **Foreign keys**: Inline with `ON DELETE CASCADE`.
- **Indexes**: Separate `CREATE INDEX IF NOT EXISTS` statements.
- **RLS**: Enable on all tables. Public read (`FOR SELECT USING
  (true)`), service role write (`FOR INSERT WITH CHECK (true)`).
- **Seed data**: `ON CONFLICT ... DO NOTHING` for idempotency.

### YAML (`.github/workflows/`)

- **Document start**: Begin with `---`.
- **Indentation**: 2 spaces.
- **Strings**: Double quotes for cron expressions and strings
  with special characters.

## GitHub Actions

- **Runner**: `ubuntu-24.04-arm` (arm64).
- **Permissions**: Minimal. Prefer `read-all` for scan workflows.
  Only `pages: write` and `id-token: write` for deploy.
- **Pin actions**: Always pin to full SHA commit hashes, not tags.
  Include a version comment (e.g. `# v6.0.2`).
- **Tool installation**: Use `jdx/mise-action` to install tools
  from `.mise.toml`. Do not use Homebrew or `actions/setup-node`.

## Version Control

- **Conventional commits**: `<type>: <description>` with types
  `feat`, `fix`, `docs`, `chore`, `refactor`, `ci`, `build`, etc.
- **Subject line**: Imperative mood, lowercase, no period, max 72
  characters.
- **Branches**: `<type>/<description>` (e.g. `feat/add-nodejs-group`,
  `fix/chart-render-bug`).
- **Pull requests**: Create as draft. Title follows conventional
  commit format.

## Supabase Data Access

- **Web app** (read): `anon` key via `@supabase/supabase-js`.
- **Scan script** (write): `service_role` key via curl to the
  PostgREST API (`$SUPABASE_URL/rest/v1/`). The `supabase` CLI
  cannot insert or select data.
- **Batch uploads**: Upload CVEs in batches of 100 to avoid
  payload limits.
