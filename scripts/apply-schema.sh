#!/usr/bin/env bash
# apply-schema.sh
#
# Links the Supabase project and pushes pending migrations.
# Requires the supabase CLI to be installed.

set -euo pipefail

# ── usage ────────────────────────────────────────────────────────
usage() {
  cat << EOF
Usage: $0 <command>

Link a Supabase project and push pending database migrations.

Commands:
  apply     Link the project and push migrations
  help      Show this help message

Required environment variables:
  SUPABASE_ACCESS_TOKEN   Supabase personal access token
  SUPABASE_PROJECT_REF    Supabase project reference ID
  SUPABASE_DB_PASSWORD    Database password

Examples:
  $0 apply               # link + push migrations
  $0 help                # show this message
EOF
}

COMMAND="${1:-help}"
case "${COMMAND}" in
  apply) ;;
  help | --help | -h)
    usage
    exit 0
    ;;
  *)
    echo "Unknown command: ${COMMAND}" >&2
    echo "" >&2
    usage >&2
    exit 1
    ;;
esac

# ── helpers ──────────────────────────────────────────────────────
die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_var() {
  [[ -n "${!1:-}" ]] || die "Environment variable $1 is not set"
}

# ── validate required environment variables ──────────────────────
require_var SUPABASE_ACCESS_TOKEN
require_var SUPABASE_PROJECT_REF
require_var SUPABASE_DB_PASSWORD

# ── link the Supabase project ───────────────────────────────────
echo "Linking Supabase project: ${SUPABASE_PROJECT_REF}"
supabase link --project-ref "${SUPABASE_PROJECT_REF}"

# ── push pending migrations ─────────────────────────────────────
echo "Pushing database migrations ..."
supabase db push --yes

echo "Done."
