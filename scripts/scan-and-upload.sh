#!/usr/bin/env bash
# scan-and-upload.sh
#
# Scans all container images listed in images.yml with trivy and grype.
# Run with "scan" to print results locally, or "upload" to push to Supabase.

set -euo pipefail

# ── usage ────────────────────────────────────────────────────────
usage() {
  cat << EOF
Usage: $0 <command>

Scan container images listed in images.yml with trivy and grype.

Commands:
  scan      Scan all images and print a CVE summary to stdout
  upload    Scan all images and upload results to Supabase
  help      Show this help message

The "upload" command requires environment variables:
  SUPABASE_URL          Supabase project URL
  SUPABASE_SERVICE_ROLE_KEY  Supabase service-role key (write access)

Examples:
  $0 scan              # local scan, print results only
  $0 upload            # scan + upload to Supabase
  $0 help              # show this message
EOF
}

COMMAND="${1:-help}"
case "${COMMAND}" in
  scan)
    UPLOAD=false
    ;;
  upload)
    UPLOAD=true
    ;;
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_FILE="${REPO_ROOT}/images.yml"

# ── helpers ──────────────────────────────────────────────────────
die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_var() {
  [[ -n "${!1:-}" ]] || die "Environment variable $1 is not set"
}

# ── function: extract CVEs from SARIF ───────────────────────────
# Outputs a JSON array of CVE objects to stdout.
# When SCAN_ID is 0 the scan_id field is omitted (local mode).
extract_cves() {
  local SARIF_FILE="$1"
  local SCAN_ID="${2:-0}"

  jq -r --argjson sid "${SCAN_ID}" '
    # Build a lookup from rule id -> rule object
    (.runs[0].tool.driver.rules // [])
      as $rules
    | ($rules | map({(.id): .}) | add // {})
      as $rule_map
    | [
        .runs[].results[]?
        | . as $result
        | $result.ruleId as $rid
        | ($rule_map[$rid] // {}) as $rule
        | {
            scan_id: (if $sid > 0 then $sid else null end),
            cve_id: $rid,
            severity: (
              $rule.defaultConfiguration.level
              // $result.level
              // "note"
              | if . == "error" then "CRITICAL"
                elif . == "warning" then "HIGH"
                elif . == "note" then "MEDIUM"
                else "LOW"
                end
            ),
            description: (
              $rule.shortDescription.text
              // $rule.fullDescription.text
              // $result.message.text
              // ""
            ),
            help_markdown: (
              $rule.help.markdown
              // $rule.help.text
              // ""
            ),
            package_name: (
              $result.locations[0]
                .logicalLocations[0].fullyQualifiedName
              // ""
            ),
            installed_version: (
              $result.message.text
              | capture("installed:\\s*(?<v>[^,]+)")
                .v // ""
            ),
            fixed_version: (
              $result.message.text
              | capture("fixed:\\s*(?<v>[^,\\s]+)")
                .v // ""
            )
          }
      ]
    | unique_by(.cve_id)
  ' "${SARIF_FILE}" 2> /dev/null || echo '[]'
}

# ── function: count CVEs by severity ─────────────────────────────
# Sets: CVE_TOTAL, CVE_CRITICAL, CVE_HIGH, CVE_MEDIUM, CVE_LOW
count_severities() {
  local CVES_JSON="$1"

  CVE_TOTAL=$(echo "${CVES_JSON}" | jq 'length')
  CVE_CRITICAL=$(echo "${CVES_JSON}" | jq '[.[] | select(.severity == "CRITICAL")] | length')
  CVE_HIGH=$(echo "${CVES_JSON}" | jq '[.[] | select(.severity == "HIGH")] | length')
  CVE_MEDIUM=$(echo "${CVES_JSON}" | jq '[.[] | select(.severity == "MEDIUM")] | length')
  CVE_LOW=$(echo "${CVES_JSON}" | jq '[.[] | select(.severity == "LOW")] | length')
}

# ── function: print CVE summary table ───────────────────────────
print_cve_summary() {
  local CVES_JSON="$1"
  local SCANNER="$2"
  local IMAGE="$3"

  count_severities "${CVES_JSON}"

  if [[ "${CVE_TOTAL}" -eq 0 ]]; then
    echo "✅ ${SCANNER}: no CVEs found"
    return
  fi

  printf "⚠️ %-6s %5d total  ( 🔴 C:%-5d 🟠 H:%-5d 🟡 M:%-5d 🔵 L:%-5d)\n" \
    "${SCANNER}" "${CVE_TOTAL}" "${CVE_CRITICAL}" "${CVE_HIGH}" "${CVE_MEDIUM}" "${CVE_LOW}"
}

# ── function: collect summary row (pipe-delimited) ──────────────
# Format: image|scanner|total|critical|high|medium|low
collect_summary() {
  local CVES_JSON="$1"
  local SCANNER="$2"
  local IMAGE="$3"

  count_severities "${CVES_JSON}"

  echo "${IMAGE}|${SCANNER}|${CVE_TOTAL}|${CVE_CRITICAL}|${CVE_HIGH}|${CVE_MEDIUM}|${CVE_LOW}"
}

# ── function: print final summary table ─────────────────────────
print_summary_table() {
  echo ""
  echo "================================================================================"
  echo "Summary"
  echo "================================================================================"
  echo ""

  # Find the longest image name for column width
  local MAX_IMG=5
  for ROW in "${SUMMARY_ROWS[@]}"; do
    local IMG="${ROW%%|*}"
    if [[ ${#IMG} -gt ${MAX_IMG} ]]; then
      MAX_IMG=${#IMG}
    fi
  done

  # Header
  printf "%-${MAX_IMG}s  %-7s  %5s  %4s  %4s  %4s  %4s\n" \
    "IMAGE" "SCANNER" "TOTAL" "CRIT" "HIGH" "MED" "LOW"
  printf "%-${MAX_IMG}s  %-7s  %5s  %4s  %4s  %4s  %4s\n" \
    "$(printf '%*s' "${MAX_IMG}" '' | tr ' ' '-')" \
    "-------" "-----" "----" "----" "----" "----"

  # Rows
  for ROW in "${SUMMARY_ROWS[@]}"; do
    IFS='|' read -r IMG SCANNER TOTAL CRIT HIGH MED LOW <<< "${ROW}"
    printf "%-${MAX_IMG}s  %-7s  %5s  %4s  %4s  %4s  %4s\n" \
      "${IMG}" "${SCANNER}" "${TOTAL}" "${CRIT}" "${HIGH}" "${MED}" "${LOW}"
  done
}

# ── function: upload CVEs to Supabase in batches ────────────────
upload_cves() {
  local CVES_JSON="$1"
  local SCANNER="$2"

  local CVE_COUNT
  CVE_COUNT=$(echo "${CVES_JSON}" | jq 'length')

  if [[ "${CVE_COUNT}" -gt 0 ]]; then
    echo "  Uploading ${CVE_COUNT} CVE records for ${SCANNER} ..."
    local BATCH_SIZE=100
    local OFFSET=0
    while [[ ${OFFSET} -lt ${CVE_COUNT} ]]; do
      local BATCH
      BATCH=$(echo "${CVES_JSON}" |
        jq ".[$OFFSET:$((OFFSET + BATCH_SIZE))]")

      local RESP_BODY
      RESP_BODY=$(echo "${BATCH}" | curl -sf \
        -H "${AUTH_HEADER}" \
        -H "${APIKEY_HEADER}" \
        -H "Content-Type: application/json" \
        -d @- \
        "${API}/cves" 2>&1) ||
        die "Failed to upload CVEs (offset ${OFFSET}) for ${SCANNER}: ${RESP_BODY}"

      OFFSET=$((OFFSET + BATCH_SIZE))
    done
  fi
}

# ── function: upload a scan record, return its id ───────────────
upload_scan() {
  local IMAGE_DB_ID="$1"
  local SCANNER="$2"
  local DIGEST="$3"
  local VERSION="$4"
  local DB_INFO="$5"
  local CVE_COUNT="$6"
  local SARIF_FILE="$7"

  local PAYLOAD
  PAYLOAD=$(jq -n \
    --argjson cid "${IMAGE_DB_ID}" \
    --arg scanner "${SCANNER}" \
    --arg digest "${DIGEST}" \
    --arg version "${VERSION}" \
    --arg db_info "${DB_INFO}" \
    --argjson count "${CVE_COUNT}" \
    --slurpfile sarif "${SARIF_FILE}" \
    '{
      container_image_id: $cid,
      scanner: $scanner,
      image_digest: $digest,
      scanner_version: $version,
      scanner_db_info: $db_info,
      cve_count: $count,
      sarif: $sarif[0]
    }')

  local RESP
  RESP=$(echo "${PAYLOAD}" | curl -sf \
    -H "${AUTH_HEADER}" \
    -H "${APIKEY_HEADER}" \
    -H "Content-Type: application/json" \
    -H "Prefer: return=representation" \
    -d @- \
    "${API}/scans" 2>&1) ||
    die "Failed to upload scan record for ${SCANNER} (image_id=${IMAGE_DB_ID}): ${RESP}"

  echo "${RESP}" | jq -r '.[0].id'
}

# ── validate inputs ─────────────────────────────────────────────
[[ -f "${IMAGES_FILE}" ]] || die "Image list not found: ${IMAGES_FILE}"

if [[ "${UPLOAD}" == "true" ]]; then
  require_var SUPABASE_URL
  require_var SUPABASE_SERVICE_ROLE_KEY
  API="${SUPABASE_URL}/rest/v1"
  AUTH_HEADER="Authorization: Bearer ${SUPABASE_SERVICE_ROLE_KEY}"
  APIKEY_HEADER="apikey: ${SUPABASE_SERVICE_ROLE_KEY}"

  # Build a lookup of image -> database id from Supabase
  IMAGES_DB_JSON=$(curl -sf \
    -H "${AUTH_HEADER}" \
    -H "${APIKEY_HEADER}" \
    -H "Content-Type: application/json" \
    "${API}/container_images?select=id,image" 2>&1) ||
    die "Failed to fetch image list from Supabase (${SUPABASE_URL}). Is the schema applied? Run: mise run db:push"
fi

# ── update vulnerability databases ───────────────────────────────
echo "📥 Updating trivy vulnerability database ..."
trivy image --download-db-only --no-progress --quiet
echo "📥 Updating grype vulnerability database ..."
grype db update

# ── collect scanner metadata ────────────────────────────────────
TRIVY_VERSION_FULL=$(trivy --version 2>&1)
TRIVY_VERSION=$(echo "${TRIVY_VERSION_FULL}" |
  grep "^Version:" |
  awk '{print $2}')
TRIVY_DB_UPDATED=$(echo "${TRIVY_VERSION_FULL}" |
  grep "UpdatedAt:" |
  head -1 |
  sed 's/.*UpdatedAt: //' |
  cut -d. -f1)

GRYPE_VERSION=$(grype version 2>&1 |
  grep "^Version:" |
  awk '{print $2}')
GRYPE_DB_STATUS=$(grype db status 2>&1)
GRYPE_DB_BUILT=$(echo "${GRYPE_DB_STATUS}" |
  grep "Built:" |
  sed 's/.*Built: *//' |
  sed 's/T/ /;s/Z$//')

echo "🔍 Trivy ${TRIVY_VERSION} (DB: ${TRIVY_DB_UPDATED})"
echo "🔍 Grype ${GRYPE_VERSION} (DB: ${GRYPE_DB_BUILT})"
echo ""

# ── read image list ─────────────────────────────────────────────
mapfile -t IMAGES < <(yq -r '.[].images[]' "${IMAGES_FILE}")
IMAGE_COUNT=${#IMAGES[@]}
echo "👉 Images to scan: ${IMAGE_COUNT}"

# Summary rows collected during scanning (printed at the end)
SUMMARY_ROWS=()

# ── scan each image ─────────────────────────────────────────────
for I in $(seq 0 $((IMAGE_COUNT - 1))); do
  IMAGE="${IMAGES[$I]}"
  IMAGE_NUM=$((I + 1))

  echo ""
  echo "================================================================================"
  echo "✴️ Scanning [${IMAGE_NUM}/${IMAGE_COUNT}]: ${IMAGE}"
  echo "================================================================================"

  # Pull the image to get the digest
  echo "🛠️ Pulling image ..."
  if ! PULL_OUTPUT=$(docker pull "${IMAGE}" 2>&1); then
    echo "${PULL_OUTPUT}" >&2
    die "Failed to pull ${IMAGE}"
  fi
  DIGEST=$(echo "${PULL_OUTPUT}" |
    grep "Digest:" |
    awk '{print $2}')
  if [[ -z "${DIGEST}" ]]; then
    DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' \
      "${IMAGE}" 2> /dev/null |
      sed 's/.*@//') || DIGEST="unknown"
  fi
  echo "💡 Digest: ${DIGEST}"

  # ── trivy scan ──────────────────────────────────────────────
  echo "⏺️ Running trivy scan ..."
  TRIVY_SARIF=$(mktemp)
  trivy image "${IMAGE}" --format sarif \
    --output "${TRIVY_SARIF}" 2>&1 || true

  TRIVY_CVES=$(extract_cves "${TRIVY_SARIF}" 0)
  TRIVY_CVE_COUNT=$(echo "${TRIVY_CVES}" | jq 'length')

  # ── grype scan ──────────────────────────────────────────────
  echo "⏺️ Running grype scan ..."
  GRYPE_SARIF=$(mktemp)
  grype "${IMAGE}" --by-cve --output sarif \
    --file "${GRYPE_SARIF}" 2>&1 || true

  GRYPE_CVES=$(extract_cves "${GRYPE_SARIF}" 0)
  GRYPE_CVE_COUNT=$(echo "${GRYPE_CVES}" | jq 'length')

  echo ""
  print_cve_summary "${TRIVY_CVES}" "trivy" "${IMAGE}"
  SUMMARY_ROWS+=("$(collect_summary "${TRIVY_CVES}" "trivy" "${IMAGE}")")
  print_cve_summary "${GRYPE_CVES}" "grype" "${IMAGE}"
  SUMMARY_ROWS+=("$(collect_summary "${GRYPE_CVES}" "grype" "${IMAGE}")")

  # ── upload to Supabase (only with --upload) ─────────────────
  if [[ "${UPLOAD}" == "true" ]]; then
    # Look up database id for this image
    IMAGE_DB_ID=$(echo "${IMAGES_DB_JSON}" |
      jq -r --arg img "${IMAGE}" '.[] | select(.image == $img) | .id')

    if [[ -z "${IMAGE_DB_ID}" ]]; then
      echo "  WARNING: image not found in Supabase, skipping upload"
    else
      # Upload trivy scan + CVEs
      TRIVY_SCAN_ID=$(upload_scan "${IMAGE_DB_ID}" "trivy" \
        "${DIGEST}" "${TRIVY_VERSION}" "" "${TRIVY_CVE_COUNT}" \
        "${TRIVY_SARIF}")
      echo "  Trivy scan saved with id=${TRIVY_SCAN_ID}"
      TRIVY_CVES_WITH_ID=$(echo "${TRIVY_CVES}" |
        jq --argjson sid "${TRIVY_SCAN_ID}" '[.[] | .scan_id = $sid]')
      upload_cves "${TRIVY_CVES_WITH_ID}" "trivy"

      # Upload grype scan + CVEs
      GRYPE_SCAN_ID=$(upload_scan "${IMAGE_DB_ID}" "grype" \
        "${DIGEST}" "grype ${GRYPE_VERSION}" "${GRYPE_DB_STATUS}" \
        "${GRYPE_CVE_COUNT}" "${GRYPE_SARIF}")
      echo "  Grype scan saved with id=${GRYPE_SCAN_ID}"
      GRYPE_CVES_WITH_ID=$(echo "${GRYPE_CVES}" |
        jq --argjson sid "${GRYPE_SCAN_ID}" '[.[] | .scan_id = $sid]')
      upload_cves "${GRYPE_CVES_WITH_ID}" "grype"
    fi
  fi

  rm -f "${TRIVY_SARIF}" "${GRYPE_SARIF}"
done

echo ""
print_summary_table
